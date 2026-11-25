import AppKit
import CirrusRetained
import Darwin
import FileProvider

@MainActor
final class ApplicationController: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate {
    private final class AccountOrigin: Sendable {
        let instance: String
        init(_ instance: String) { self.instance = instance }
    }
    private final class SpacesView: Sendable {
        let account: AccountOrigin
        let values: [ApplicationSpace]
        let next: Int
        init(account: AccountOrigin, values: [ApplicationSpace], next: Int) {
            self.account = account; self.values = values; self.next = next
        }
    }
    private final class Selection: Sendable {
        let page: SpacesView
        let space: ApplicationSpace
        init(page: SpacesView, space: ApplicationSpace) { self.page = page; self.space = space }
    }
    private enum Origin: Sendable {
        case account(AccountOrigin)
        case spaces(SpacesView)
        case selection(Selection)
        case restoration
    }
    private final class Request: Sendable {
        let origin: Origin
        init(_ origin: Origin) { self.origin = origin }
    }
    private enum Phase {
        case idle
        case connecting(Request)
        case signInResult(Request)
        case working(Request)
        case registering(Request)
        case terminating

        var request: Request? {
            switch self {
            case .connecting(let request), .signInResult(let request),
                 .working(let request), .registering(let request): return request
            case .idle, .terminating: return nil
            }
        }
        var isIdle: Bool {
            if case .idle = self { return true }
            return false
        }
        var isTerminating: Bool {
            if case .terminating = self { return true }
            return false
        }
        var canCancel: Bool {
            if case .connecting = self { return true }
            return false
        }
    }
    private let configuration: ApplicationConfiguration
    private var worker: ApplicationWorker?
    private var window: NSWindow!
    private let instance = NSTextField()
    private let status = NSTextField(wrappingLabelWithString: "")
    private let syncStatus = NSTextField(wrappingLabelWithString: "Automatic sync observes mounted Spaces.")
    private let spaces = NSPopUpButton()
    private var connectButton: NSButton!
    private var cancelButton: NSButton!
    private var discoverButton: NSButton!
    private var mountButton: NSButton!
    private let registration = FinderRegistration()
    private var moreSpacesButton: NSButton!
    private var account: AccountOrigin
    private var spacePage: SpacesView?
    private var selection: Selection?
    private var phase: Phase = .idle

    init(_ configuration: ApplicationConfiguration) {
        self.configuration = configuration
        account = AccountOrigin(configuration.instance)
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        worker = ApplicationWorker(configuration, syncObservation: { [weak self] observation in
            guard let self, !self.phase.isTerminating else { return }
            guard let observation else {
                self.syncStatus.stringValue = "Automatic sync is waiting for account or storage access. Local changes are retained."
                return
            }
            if let state = observation.status {
                switch state.phase {
                case "Queued", "Uploading": self.syncStatus.stringValue = "\(state.queued) upload(s) pending."
                case "Verifying": self.syncStatus.stringValue = "Verifying uploaded changes."
                case "Attention":
                    self.syncStatus.stringValue = "Changes need attention; local data is retained. " + (state.cause ?? "Inspect the account or conflicting file before retrying.")
                case "Retry": self.syncStatus.stringValue = "Sync will retry automatically. " + (state.cause ?? "Waiting for connectivity.")
                default: self.syncStatus.stringValue = "No pending uploads observed. Cloud-wide freshness is not asserted."
                }
            }
            for id in observation.domains {
                let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: id), displayName: "Cirrus Space")
                NSFileProviderManager(for: domain)?.signalEnumerator(for: .workingSet) { _ in }
            }
        })
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 380),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Cirrus — Development"
        window.minSize = NSSize(width: 680, height: 380)
        window.delegate = self
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 16
        root.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 24, right: 24)
        root.translatesAutoresizingMaskIntoConstraints = false
        window.contentView?.addSubview(root)
        if let content = window.contentView {
            NSLayoutConstraint.activate([
                root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
                root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
                root.topAnchor.constraint(equalTo: content.topAnchor),
                root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
            ])
        }
        let heading = NSTextField(labelWithString: "Mount your OpenCloud Spaces")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        root.addArrangedSubview(heading)
        let note = NSTextField(wrappingLabelWithString:
            "Mounting a Space enables sync and requests Finder registration. Browse files in Finder once the Space is available there. " +
            "Finder changes are uploaded automatically; conflicts and uncertain outcomes retain local data. " +
            "Unsigned builds cannot open protected account storage without the required entitlements.")
        note.textColor = .secondaryLabelColor
        root.addArrangedSubview(note)
        instance.stringValue = configuration.instance
        instance.delegate = self
        instance.placeholderString = "https://your-opencloud-server"
        instance.setAccessibilityLabel("OpenCloud instance URL")
        root.addArrangedSubview(instance)
        connectButton = button("Connect in Browser", #selector(connect))
        cancelButton = button("Cancel Sign-In", #selector(cancel))
        discoverButton = button("Load Spaces", #selector(discover))
        let accountRow = NSStackView(views: [connectButton, cancelButton, discoverButton])
        accountRow.spacing = 8
        root.addArrangedSubview(accountRow)
        spaces.setAccessibilityLabel("Authenticated Spaces")
        spaces.target = self; spaces.action = #selector(selectionChanged)
        spaces.addItem(withTitle: "Load Spaces to choose a Space")
        mountButton = button("Mount Space", #selector(mountSpace))
        moreSpacesButton = button("More Spaces", #selector(moreSpaces))
        let spaceRow = NSStackView(views: [spaces, mountButton, moreSpacesButton])
        spaceRow.spacing = 8
        root.addArrangedSubview(spaceRow)
        status.stringValue = "Ready. Load a saved account’s Spaces, or connect in your browser."
        status.setAccessibilityRole(.staticText)
        root.addArrangedSubview(status)
        syncStatus.textColor = .secondaryLabelColor
        syncStatus.setAccessibilityRole(.staticText)
        root.addArrangedSubview(syncStatus)
        for view in [note, instance, spaceRow, status, syncStatus] {
            view.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -48).isActive = true
        }
        let menu = NSMenu()
        let appItem = NSMenuItem()
        menu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Cirrus", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        NSApp.mainMenu = menu
        updateControls()
        restoreMounts()
        window.center(); window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    private func button(_ title: String, _ action: Selector) -> NSButton {
        NSButton(title: title, target: self, action: action)
    }
    private func updateControls() {
        let idle = phase.isIdle
        instance.isEnabled = idle
        connectButton.isEnabled = idle
        discoverButton.isEnabled = idle
        cancelButton.isEnabled = phase.canCancel
        spaces.isEnabled = idle && !(spacePage?.values.isEmpty ?? true)
        mountButton.isEnabled = idle && selection.map { isCurrent(.selection($0)) } == true
        moreSpacesButton.isEnabled = idle && (spacePage?.next ?? 0) > 0
    }
    private func isCurrent(_ origin: Origin) -> Bool {
        switch origin {
        case .account(let captured):
            return account === captured && instance.stringValue == captured.instance
        case .spaces(let captured):
            return spacePage === captured && isCurrent(.account(captured.account))
        case .selection(let captured):
            return selection === captured && isCurrent(.spaces(captured.page)) &&
                captured.page.values.indices.contains(spaces.indexOfSelectedItem) &&
                captured.page.values[spaces.indexOfSelectedItem].id == captured.space.id
        case .restoration:
            return true
        }
    }
    private func finish(_ request: Request) -> Bool {
        guard phase.request === request else { return false }
        phase = .idle
        guard isCurrent(request.origin) else { updateControls(); return false }
        return true
    }
    private func perform(_ operation: ApplicationOperation, from origin: Origin, message: String,
                         success: @escaping @MainActor @Sendable (ApplicationReply) -> Void) {
        guard phase.isIdle, isCurrent(origin), let worker else { return }
        let request = Request(origin)
        if case .connect = operation { phase = .connecting(request) }
        else { phase = .working(request) }
        status.stringValue = message; updateControls()
        worker.submit(operation) { [weak self] result in
            guard let self, self.finish(request) else { return }
            switch result {
            case .success(let reply): success(reply)
            case .failure(let error):
                if let retained = error as? RetainedError, case .internalFailure = retained {
                    self.invalidateSpaces()
                }
                if case ApplicationError.protectedStorageUnavailable = error {
                    self.status.stringValue = "Protected storage unavailable. This process needs the configured App Group " +
                        "and separate Keychain entitlements, plus an admitted physical container. Unsigned builds have no storage fallback."
                } else if let retained = error as? RetainedError {
                    switch retained {
                    case .cancelled: self.status.stringValue = "Sign-in cancelled. You can try again."
                    case .capacity: self.status.stringValue = "The bounded metadata capacity was exceeded."
                    case .invalidABI: self.status.stringValue = "Invalid configuration or request. Check the supplied identifiers and URL."
                    default:
                        self.status.stringValue = "Account unavailable. Check App Group and separate Keychain entitlements, " +
                            "container permissions, sign-in and server access. No successful cloud read is claimed."
                    }
                } else { self.status.stringValue = "The operation failed. No successful cloud read is claimed." }
            }
            self.updateControls()
        }
    }
    private func invalidateSpaces() {
        spacePage = nil; selection = nil
        spaces.removeAllItems()
        spaces.addItem(withTitle: "Load Spaces to choose a Space")
    }
    func controlTextDidChange(_ notification: Notification) {
        guard notification.object as? NSTextField === instance, !phase.isTerminating else { return }
        account = AccountOrigin(instance.stringValue)
        invalidateSpaces()
        status.stringValue = "Load Spaces or connect to verify this server."
        updateControls()
    }
    private func receivedSpaces(_ reply: ApplicationReply, from origin: AccountOrigin) {
        guard case .spaces(let values, let next) = reply else { return }
        spacePage = SpacesView(account: origin, values: values, next: values.isEmpty ? 0 : next)
        spaces.removeAllItems()
        if values.isEmpty { spaces.addItem(withTitle: "No more Spaces") }
        else { for value in values { spaces.addItem(withTitle: value.name) } }
        updateSelection()
        status.stringValue = values.isEmpty ? "No Spaces on this page." :
            "\(values.count) authenticated Spaces on this page. Choose one to mount."
    }
    @objc private func connect() {
        guard phase.isIdle else { return }
        invalidateSpaces()
        let origin = account
        perform(.connect(origin.instance), from: .account(origin), message: "Connecting. Complete sign-in in your browser…") { [weak self] _ in
            self?.status.stringValue = "Connected. Load Spaces to verify current membership."
        }
    }
    @objc private func cancel() {
        guard case .connecting(let request) = phase else { return }
        phase = .signInResult(request)
        let code = worker?.cancelConnect() ?? Int32(CIRRUS_UNAVAILABLE)
        cancelButton.isEnabled = false
        status.stringValue = code == Int32(CIRRUS_OK) ? "Cancellation requested. Waiting for the sign-in result…" :
            code == Int32(CIRRUS_SIGNIN_FINISHING) ? "Sign-in is finishing; cancellation did not take effect. Waiting for its result…" :
            "Cancellation unavailable. Waiting for the sign-in result…"
    }
    @objc private func discover() {
        guard phase.isIdle else { return }
        invalidateSpaces()
        let origin = account
        perform(.spaces(origin.instance), from: .account(origin), message: "Loading authenticated Spaces…") { [weak self] in
            self?.receivedSpaces($0, from: origin)
        }
    }
    @objc private func moreSpaces() {
        guard phase.isIdle, let origin = spacePage, isCurrent(.spaces(origin)), origin.next > 0 else { return }
        perform(.spacePage(origin.next), from: .spaces(origin), message: "Loading next Space page…") { [weak self] in
            self?.receivedSpaces($0, from: origin.account)
        }
    }
    private func updateSelection() {
        guard let page = spacePage, isCurrent(.spaces(page)),
              page.values.indices.contains(spaces.indexOfSelectedItem) else {
            selection = nil; return
        }
        let chosen = page.values[spaces.indexOfSelectedItem]
        if let selection, selection.page === page, selection.space.id == chosen.id { return }
        selection = Selection(page: page, space: chosen)
    }
    @objc private func selectionChanged() {
        guard !phase.isTerminating else { return }
        updateSelection()
        if selection != nil {
            status.stringValue = "Space selected. Mount it for Finder access."
        }
        updateControls()
    }
    @objc private func mountSpace() {
        guard phase.isIdle, let selected = selection, isCurrent(.selection(selected)), let worker else { return }
        let request = Request(.selection(selected))
        phase = .registering(request)
        status.stringValue = "Mounting Space…"
        registration.mount(instance: selected.page.account.instance, space: selected.space, worker: worker) { [weak self] outcome in
            guard let self, self.finish(request) else { return }
            self.status.stringValue = outcome.message
            self.updateControls()
        }
        updateControls()
    }
    private func restoreMounts() {
        guard phase.isIdle, let worker else { return }
        let request = Request(.restoration)
        phase = .registering(request); updateControls()
        registration.restore(worker: worker) { [weak self] outcome in
            guard let self, self.finish(request) else { return }
            // No modal, confirmation or happy-path setup gate on restoration.
            if !outcome.ready { self.status.stringValue = outcome.message }
            self.updateControls()
        }
    }
    func applicationDidBecomeActive(_ notification: Notification) { restoreMounts() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApp.terminate(nil); return false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if phase.isTerminating { return .terminateLater }
        phase = .terminating
        updateControls()
        guard let worker else { return .terminateNow }
        status.stringValue = "Waiting for account operations to finish safely…"
        registration.drain {
            worker.shutdown { [weak self] in
                self?.worker = nil
                NSApp.reply(toApplicationShouldTerminate: true)
            }
        }
        return .terminateLater
    }
}

// Headless commands never initialize NSApplication, launch a browser or access
// credentials. Admission only calls the existing entitlement-first constructor.
let arguments = Array(CommandLine.arguments.dropFirst())
do {
    guard arguments.count == 2,
          ["--config", "--validate-config", "--check-admission"].contains(arguments[0])
    else { throw ConfigurationError.usage }
    let configuration = try ApplicationConfiguration.read(arguments[1])
    switch arguments[0] {
    case "--validate-config":
        print("Configuration valid; entitlements, credentials and connectivity NOT checked.")
    case "--check-admission":
        do {
            _ = try RetainedCore(appGroup: configuration.appGroup, keychainAccessGroup: configuration.keychainGroup)
            print("Protected storage admitted; authentication NOT checked.")
        } catch {
            fputs("Protected storage unavailable; required App Group/separate Keychain entitlements or strict container admission failed. No fallback.\n", stderr)
            exit(3)
        }
    default:
        let application = NSApplication.shared
        let controller = ApplicationController(configuration)
        application.setActivationPolicy(.regular)
        application.delegate = controller
        application.run()
        withExtendedLifetime(controller) {}
    }
} catch {
    fputs("Usage: CirrusApplication (--config | --validate-config | --check-admission) explicit-config.json\nConfiguration requires only nonempty appGroup, keychainGroup and an HTTPS instance URL without credentials, query or fragment. No default identifiers or storage paths.\n", stderr)
    exit(2)
}
