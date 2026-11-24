import AppKit
import CirrusRetained
import Darwin
import FileProvider

@MainActor
final class ApplicationController: NSObject, NSApplicationDelegate, NSWindowDelegate,
                                   NSTableViewDataSource, NSTableViewDelegate, NSTextFieldDelegate {
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
    private struct Breadcrumb: Sendable {
        let name: String
        let id: String
    }
    private final class DirectoryView: Sendable {
        let selection: Selection
        let breadcrumbs: [Breadcrumb]
        let entries: [RetainedEntry]
        let next: UInt64
        init(selection: Selection, breadcrumbs: [Breadcrumb], entries: [RetainedEntry], next: UInt64) {
            self.selection = selection; self.breadcrumbs = breadcrumbs
            self.entries = entries; self.next = next
        }
    }
    private enum Origin: Sendable {
        case account(AccountOrigin)
        case spaces(SpacesView)
        case selection(Selection)
        case directory(DirectoryView)
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
    private let location = NSTextField(labelWithString: "/")
    private let spaces = NSPopUpButton()
    private let table = NSTableView()
    private var connectButton: NSButton!
    private var cancelButton: NSButton!
    private var discoverButton: NSButton!
    private var bindButton: NSButton!
    private let registration = FinderRegistration()
    private var moreSpacesButton: NSButton!
    private var upButton: NSButton!
    private var openButton: NSButton!
    private var nextButton: NSButton!
    private var account: AccountOrigin
    private var spacePage: SpacesView?
    private var selection: Selection?
    private var directory: DirectoryView?
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
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 620),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Cirrus — Development"
        window.minSize = NSSize(width: 680, height: 520)
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
        let heading = NSTextField(labelWithString: "Browse your OpenCloud Spaces")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        root.addArrangedSubview(heading)
        let note = NSTextField(wrappingLabelWithString:
            "Mounting a Space enables sync and automatically makes it available in Finder and offers observed metadata to Spotlight. " +
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
        bindButton = button("Mount Space", #selector(browseSpace))
        moreSpacesButton = button("More Spaces", #selector(moreSpaces))
        let spaceRow = NSStackView(views: [spaces, bindButton, moreSpacesButton])
        spaceRow.spacing = 8
        root.addArrangedSubview(spaceRow)
        upButton = button("Up", #selector(up))
        location.lineBreakMode = .byTruncatingMiddle
        location.setAccessibilityLabel("Current directory")
        let directoryRow = NSStackView(views: [upButton, location])
        directoryRow.spacing = 12
        root.addArrangedSubview(directoryRow)
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name"))
        column.title = "Name"; column.width = 690
        table.addTableColumn(column)
        table.dataSource = self; table.delegate = self
        table.target = self; table.doubleAction = #selector(openDirectory)
        table.setAccessibilityLabel("Directory contents")
        table.usesAlternatingRowBackgroundColors = true
        let scroll = NSScrollView()
        scroll.documentView = table; scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        root.addArrangedSubview(scroll)
        openButton = button("Open Directory", #selector(openDirectory))
        nextButton = button("Next Page", #selector(nextPage))
        let pageRow = NSStackView(views: [openButton, nextButton])
        pageRow.spacing = 8
        root.addArrangedSubview(pageRow)
        status.stringValue = "Ready. Load a saved account’s Spaces, or connect in your browser."
        status.setAccessibilityRole(.staticText)
        root.addArrangedSubview(status)
        syncStatus.textColor = .secondaryLabelColor
        syncStatus.setAccessibilityRole(.staticText)
        root.addArrangedSubview(syncStatus)
        for view in [note, instance, spaceRow, directoryRow, scroll, status, syncStatus] {
            view.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -48).isActive = true
        }
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
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
        let view = currentDirectory
        instance.isEnabled = idle && view == nil
        connectButton.isEnabled = idle
        discoverButton.isEnabled = idle
        cancelButton.isEnabled = phase.canCancel
        spaces.isEnabled = idle && !(spacePage?.values.isEmpty ?? true)
        bindButton.isEnabled = idle && selection.map { isCurrent(.selection($0)) } == true
        moreSpacesButton.isEnabled = idle && (spacePage?.next ?? 0) > 0
        upButton.isEnabled = idle && !(view?.breadcrumbs.isEmpty ?? true)
        openButton.isEnabled = idle && view.map {
            $0.entries.indices.contains(table.selectedRow) && $0.entries[table.selectedRow].directory
        } == true
        nextButton.isEnabled = idle && view.map { !$0.entries.isEmpty } == true
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
        case .directory(let captured):
            return directory === captured && isCurrent(.selection(captured.selection))
        case .restoration:
            return true
        }
    }
    private var currentDirectory: DirectoryView? {
        guard let directory, isCurrent(.directory(directory)) else { return nil }
        return directory
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
                if case .directory = request.origin { self.resetBrowser() }
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
    private func resetBrowser() {
        directory = nil; table.reloadData(); location.stringValue = "/"
    }
    private func invalidateSpaces() {
        spacePage = nil; selection = nil
        spaces.removeAllItems()
        spaces.addItem(withTitle: "Load Spaces to choose a Space")
        resetBrowser()
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
            "\(values.count) authenticated Spaces on this page. Choose one to browse."
    }
    private func receivedDirectory(_ reply: ApplicationReply, selection: Selection,
                                   breadcrumbs: [Breadcrumb]) {
        guard case .directory(let values, let next) = reply else { return }
        directory = DirectoryView(selection: selection, breadcrumbs: breadcrumbs, entries: values, next: next)
        table.reloadData()
        location.stringValue = "/" + breadcrumbs.map { $0.name }.joined(separator: "/")
        status.stringValue = values.isEmpty ? "End of this directory listing." :
            "\(values.count) entries on this page. Metadata is a demand-read observation, not continuous synchronization."
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
        resetBrowser()
        perform(.spacePage(origin.next), from: .spaces(origin), message: "Loading next Space page…") { [weak self] in
            self?.receivedSpaces($0, from: origin.account)
        }
    }
    private func updateSelection() {
        guard let page = spacePage, isCurrent(.spaces(page)),
              page.values.indices.contains(spaces.indexOfSelectedItem) else {
            selection = nil; resetBrowser(); return
        }
        let chosen = page.values[spaces.indexOfSelectedItem]
        if let selection, selection.page === page, selection.space.id == chosen.id { return }
        selection = Selection(page: page, space: chosen)
        resetBrowser()
    }
    @objc private func selectionChanged() {
        guard !phase.isTerminating else { return }
        updateSelection()
        if selection != nil && currentDirectory == nil {
            status.stringValue = "Space selected. Mount it to open a freshly verified listing."
        }
        updateControls()
    }
    @objc private func browseSpace() {
        guard phase.isIdle, let selected = selection, isCurrent(.selection(selected)), let worker else { return }
        resetBrowser()
        let request = Request(.selection(selected))
        phase = .registering(request)
        status.stringValue = "Mounting Space…"
        registration.mount(instance: selected.page.account.instance, space: selected.space, worker: worker) { [weak self] outcome in
            guard let self, self.finish(request) else { return }
            self.status.stringValue = outcome.message
            if outcome.ready {
                self.perform(.bind(instance: selected.page.account.instance, space: selected.space.id),
                             from: .selection(selected), message: outcome.message) { [weak self] reply in
                    self?.receivedDirectory(reply, selection: selected, breadcrumbs: [])
                    self?.status.stringValue = outcome.message
                }
            }
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
            if !outcome.ready { self.resetBrowser(); self.status.stringValue = outcome.message }
            self.updateControls()
        }
    }
    func applicationDidBecomeActive(_ notification: Notification) { restoreMounts() }
    @objc private func openDirectory() {
        guard phase.isIdle, let view = currentDirectory, view.entries.indices.contains(table.selectedRow),
              view.entries[table.selectedRow].directory else { return }
        let entry = view.entries[table.selectedRow]
        let destination = view.breadcrumbs + [Breadcrumb(name: entry.name, id: entry.id)]
        perform(.directory(path: destination.map { $0.name }, parentID: entry.id),
                from: .directory(view), message: "Reading directory…") { [weak self] reply in
            self?.receivedDirectory(reply, selection: view.selection, breadcrumbs: destination)
        }
    }
    @objc private func up() {
        guard phase.isIdle, let view = currentDirectory, !view.breadcrumbs.isEmpty else { return }
        let destination = Array(view.breadcrumbs.dropLast())
        perform(.directory(path: destination.map { $0.name }, parentID: destination.last?.id ?? ""),
                from: .directory(view), message: "Reading parent directory…") { [weak self] reply in
            self?.receivedDirectory(reply, selection: view.selection, breadcrumbs: destination)
        }
    }
    @objc private func nextPage() {
        guard phase.isIdle, let view = currentDirectory, !view.entries.isEmpty else { return }
        perform(.directoryPage(view.next), from: .directory(view), message: "Reading next metadata page…") { [weak self] in
            self?.receivedDirectory($0, selection: view.selection, breadcrumbs: view.breadcrumbs)
        }
    }
    func numberOfRows(in tableView: NSTableView) -> Int { currentDirectory?.entries.count ?? 0 }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let view = currentDirectory, view.entries.indices.contains(row) else { return nil }
        let entry = view.entries[row]
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: entry.name)
        label.lineBreakMode = .byTruncatingMiddle
        let image = NSImageView()
        image.image = NSImage(systemSymbolName: entry.directory ? "folder" : "doc", accessibilityDescription: entry.directory ? "Directory" : "File")
        let stack = NSStackView(views: [image, label])
        stack.spacing = 8; stack.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
            stack.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -6),
            stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }
    func tableViewSelectionDidChange(_ notification: Notification) { updateControls() }
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
