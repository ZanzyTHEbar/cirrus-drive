//! Bounded read-plan ABI. No instructions can access files or issue effects.

use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

use crate::CachedRange;

const MAX_FRAGMENTS: usize = 4;
const PROGRAM_BITS: u32 = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Rule {
    FetchExact = 0,
    Cover = 1,
    Stitch = 2,
}

/// A validated staged-file cache-miss program for the resident read-plan ABI.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadProgram(u8);

impl ReadProgram {
    /// Negotiates the artifact's role, ABI and bounded instruction sequence.
    pub fn negotiate(bytes: &[u8]) -> io::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Artifact {
            role: String,
            abi: u8,
            rules: Vec<Rule>,
        }
        let artifact: Artifact = serde_json::from_slice(bytes)?;
        if artifact.abi != 1 || artifact.role != "mounted-staged-read-plan" {
            return Err(io::Error::other(
                "incompatible mounted read-engine role or ABI",
            ));
        }
        const BAD_RULES: &str = "invalid mounted read-engine instruction sequence";
        let Some((Rule::FetchExact, rules)) = artifact.rules.split_last() else {
            return Err(io::Error::other(BAD_RULES));
        };
        if rules.len() > 2
            || rules.contains(&Rule::FetchExact)
            || (rules.len() == 2 && rules[0] == rules[1])
        {
            return Err(io::Error::other(BAD_RULES));
        }
        let code = rules.iter().enumerate().fold(0, |code, (index, rule)| {
            code | ((*rule as u8) << (index * 2))
        });
        Ok(Self(code))
    }
}

/// The single resident-owned program slot shared by all mounted drives.
#[derive(Debug, Default)]
pub struct ReadEngines(AtomicU64);

impl ReadEngines {
    /// Maximum generation that can be packed atomically with a program.
    pub const MAX_GENERATION: u64 = u64::MAX >> PROGRAM_BITS;

    /// Publishes the next negotiated generation. The resident serializes publishers.
    pub fn publish(&self, generation: u64, program: ReadProgram) {
        assert!(
            generation <= Self::MAX_GENERATION && generation > self.snapshot().generation(),
            "read engine must advance to a representable generation"
        );
        self.0.store(
            generation << PROGRAM_BITS | u64::from(program.0),
            Ordering::SeqCst,
        );
    }

    pub(crate) fn snapshot(&self) -> ProgramEpoch {
        ProgramEpoch(self.0.load(Ordering::SeqCst))
    }

    /// Linearizes admission of a pure result before or after publication.
    /// Admitted reads can finish only through the same resident executor.
    pub(crate) fn admit(&self, epoch: ProgramEpoch) -> bool {
        self.snapshot().0 == epoch.0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProgramEpoch(u64);

impl ProgramEpoch {
    fn generation(self) -> u64 {
        self.0 >> PROGRAM_BITS
    }

    pub(crate) fn can_reuse(self) -> bool {
        self.0 as u8 != 0
    }

    /// The caller supplies only ranges for the exact staged file version.
    pub(crate) fn plan(
        self,
        request: Range<u64>,
        ranges: &[Arc<CachedRange>],
    ) -> Option<CachePlan> {
        let mut code = self.0 as u8;
        while code != 0 {
            let plan = match code & 3 {
                1 => plan_cover(&request, ranges),
                2 => plan_stitch(&request, ranges),
                _ => return None,
            };
            if plan.is_some() {
                return plan;
            }
            code >>= 2;
        }
        None
    }
}

pub(crate) struct CachePlan(Vec<Arc<CachedRange>>);

impl CachePlan {
    /// Independently check contiguous, exact output before copying each fragment.
    pub(crate) fn assemble(self, request: Range<u64>) -> Option<Vec<u8>> {
        let length = usize::try_from(request.end.checked_sub(request.start)?).ok()?;
        let mut result = Vec::with_capacity(length);
        let mut cursor = request.start;
        for range in self.0 {
            let end = range_end(&range)?.min(request.end);
            if cursor >= end {
                return None;
            }
            let start = usize::try_from(cursor.checked_sub(range.offset)?).ok()?;
            let stop = usize::try_from(end.checked_sub(range.offset)?).ok()?;
            result.extend_from_slice(range.bytes.get(start..stop)?);
            cursor = end;
        }
        (cursor == request.end).then_some(result)
    }
}

fn range_end(range: &CachedRange) -> Option<u64> {
    range.offset.checked_add(range.bytes.len() as u64)
}

fn plan_cover(request: &Range<u64>, ranges: &[Arc<CachedRange>]) -> Option<CachePlan> {
    let range = ranges.iter().find(|range| {
        range.offset <= request.start && range_end(range).is_some_and(|end| end >= request.end)
    })?;
    Some(CachePlan(vec![Arc::clone(range)]))
}

fn plan_stitch(request: &Range<u64>, ranges: &[Arc<CachedRange>]) -> Option<CachePlan> {
    let mut cursor = request.start;
    let mut parts = Vec::new();
    for _ in 0..MAX_FRAGMENTS {
        let (end, source) = ranges
            .iter()
            .filter_map(|range| {
                let end = range_end(range)?;
                (range.offset <= cursor && end > cursor).then_some((end, range))
            })
            .max_by_key(|(end, _)| *end)?;
        parts.push(Arc::clone(source));
        if end >= request.end {
            return Some(CachePlan(parts));
        }
        cursor = end;
    }
    None
}
