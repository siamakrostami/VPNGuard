import SwiftUI
import VPNGuardCore

struct GuardWindow: View {
    @Bindable var model: GuardModel
    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "shield.lefthalf.filled").font(.title2).foregroundStyle(.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("VPNGuard").font(.headline)
                        Text("Protected launches").font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.horizontal, 18).padding(.top, 24).padding(.bottom, 26)
                List(selection: $model.section) {
                    ForEach(GuardSection.allCases) { section in
                        Label(section.rawValue, systemImage: section.symbol).tag(section)
                            .padding(.vertical, 4)
                    }
                }.listStyle(.sidebar)
                Divider().padding(.horizontal, 16)
                VStack(alignment: .leading, spacing: 9) {
                    Label(model.statusTitle, systemImage: model.statusSymbol)
                        .font(.caption.weight(.semibold)).foregroundStyle(model.statusColor)
                    Text("\(model.enabledCount) items require a VPN").font(.caption).foregroundStyle(.secondary)
                }.padding(18)
            }.navigationSplitViewColumnWidth(min: 195, ideal: 210, max: 250)
        } detail: {
            VStack(spacing: 0) {
                if let error = model.error { banner(error, warning: true) { model.error = nil } }
                if let notice = model.notice { banner(notice, warning: false) { model.notice = nil } }
                switch model.section {
                case .overview: overview
                case .rules: rules
                case .activity: activity
                case .settings: settings
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationTitle(model.section.rawValue)
                .toolbar {
                    ToolbarItemGroup {
                        Button("Verify connection", systemImage: "arrow.clockwise") { Task { await model.checkVPN() } }.disabled(model.isChecking)
                        Button("Reset connections", systemImage: "arrow.triangle.2.circlepath") { model.resetActiveConnections() }
                            .disabled(!model.sessions.contains(where: model.canReset))
                            .help("Close current protected connections and verify the VPN again. Then retry your prompt.")
                        Button("Add Item", systemImage: "plus") { model.showingAdd = true }.keyboardShortcut("n", modifiers: .command)
                    }
                }
        }
        .frame(minWidth: 900, minHeight: 650)
        .sheet(isPresented: $model.showingAdd) { RuleEditor(model: model, original: nil) }
        .sheet(item: $model.editing) { item in RuleEditor(model: model, original: item) }
        .confirmationDialog("Remove this rule?", isPresented: Binding(get: { model.pendingRemoval != nil }, set: { if !$0 { model.pendingRemoval = nil } }), titleVisibility: .visible) {
            if let item = model.pendingRemoval {
                Button("Remove \(item.name)", role: .destructive) { model.remove(item); model.pendingRemoval = nil }
            }
            Button("Cancel", role: .cancel) { model.pendingRemoval = nil }
        } message: {
            Text("New launches will no longer be guarded by this rule. Existing sessions for this rule will be resumed if needed and terminated. Open a new Terminal window after changing command rules.")
        }
        .alert("Launch an app with network isolation?", isPresented: Binding(get: { model.pendingDesktopLaunch != nil }, set: { if !$0 { model.pendingDesktopLaunch = nil } })) {
            Button("Cancel", role: .cancel) { model.pendingDesktopLaunch = nil }
            Button("Launch Through VPNGuard") {
                if let item = model.pendingDesktopLaunch { model.pendingDesktopLaunch = nil; Task { await model.run(item) } }
            }
        } message: {
            Text("Quit any existing instance first. Direct sockets and inherited child processes are restricted. Apps that hand work to independent background services may need additional validation; VPNGuard cannot intercept normal Finder launches.")
        }
        .confirmationDialog("Uninstall VPNGuard?",isPresented:$model.showingUninstall,titleVisibility:.visible) {
            Button("Stop sessions and uninstall",role:.destructive) { model.uninstall() }
            Button("Cancel",role:.cancel) {}
        } message: {
            Text("Protected commands and applications will be terminated. VPNGuard’s login/background registration and recognized local files will be removed. Other VPN software will not be changed.")
        }
        .task { model.start() }
    }
    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                HStack(alignment: .top, spacing: 20) {
                    Image(systemName: model.statusSymbol).font(.system(size: 44, weight: .light)).foregroundStyle(model.statusColor).frame(width: 58).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.statusTitle).font(.largeTitle.weight(.semibold))
                        Text(model.networkMessage).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    if model.isChecking { ProgressView().controlSize(.small).padding(.top, 12) }
                }.padding(.vertical, 8)
                HStack(spacing: 16) {
                    metric("Exit country", value: model.countryName, symbol: "globe.europe.africa")
                    metric("Public IP", value: model.vpnReady ? (model.verification?.exit.address ?? "Not verified") : "Not verified", symbol: "network")
                    metric("Guarded sessions", value: "\(model.activeSessions.count)", symbol: "terminal")
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 18) {
                        HStack {
                            Label("VPN required", systemImage: "checklist").font(.headline)
                            Spacer()
                            Button("View All") { model.section = .rules }.buttonStyle(.link)
                        }
                        if model.rules.isEmpty { Text("Add a command or application to create your first rule.").foregroundStyle(.secondary) }
                        ForEach(model.rules.prefix(4)) { item in compactRule(item) }
                        Button("Add Application or Command", systemImage: "plus") { model.showingAdd = true }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack(alignment: .top, spacing: 18) {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("Type commands normally", systemImage: "terminal").font(.headline)
                            Text(model.integrationInstalled ? "Command integration is installed. Open a new Terminal window after changing rules." : "Install the zsh integration to check the VPN whenever you type claude, codex, or another selected command.")
                                .font(.callout).foregroundStyle(.secondary)
                            Button(model.integrationInstalled ? "Manage Integration" : "Set Up Command Integration") {
                                if model.integrationInstalled { model.section = .settings } else { model.installIntegration() }
                            }.buttonStyle(.borderedProminent).tint(.teal)
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("How protection works", systemImage: "lock.shield").font(.headline)
                            Text("Guarded launches can reach only their private local proxy. Connections close when VPN verification is lost and resume only after a fresh check.")
                                .font(.callout).foregroundStyle(.secondary)
                            Text("Other apps keep their normal connection.").font(.caption.weight(.medium))
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Label("Desktop apps must be launched through VPNGuard. HTTPS proxy compatibility varies; ordinary Finder launches are outside its control.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }.padding(30).frame(maxWidth: 1040, alignment: .leading).frame(maxWidth: .infinity)
        }
    }
    private var rules: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Choose what needs a VPN").font(.title2.weight(.semibold))
                    Text("A connected tunnel and a verified exit outside Iran are required.").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Add Item", systemImage: "plus") { model.showingAdd = true }.buttonStyle(.borderedProminent).tint(.teal)
            }.padding(26)
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search apps, commands or paths", text: $model.search).textFieldStyle(.plain)
                if !model.search.isEmpty { Button("Clear", systemImage: "xmark.circle.fill") { model.search = "" }.labelStyle(.iconOnly).buttonStyle(.plain) }
            }.padding(10).background(.quaternary, in: RoundedRectangle(cornerRadius: 9)).padding(.horizontal, 26).padding(.bottom, 16)
            if model.filteredRules.isEmpty {
                ContentUnavailableView(model.search.isEmpty ? "No protected items" : "No matching items", systemImage: "checklist", description: Text(model.search.isEmpty ? "Add an app bundle or a command executable to begin." : "Try another name or executable path."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $model.selectedRule) {
                    ForEach(model.filteredRules) { item in
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 14) {
                                targetIcon(item).frame(width: 34, height: 34)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.name).font(.headline)
                                    Text(item.kind == .command ? "Command · \(item.commandName ?? "")" : "Application · launch through VPNGuard")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Toggle("Require VPN for \(item.name)", isOn: Binding(get: { item.isEnabled }, set: { model.toggle(item, enabled: $0) })).labelsHidden().toggleStyle(.switch).controlSize(.small)
                                Button("Launch", systemImage: "play.fill") { model.launch(item) }.disabled(!item.isEnabled || !model.preferences.protectionEnabled)
                                Menu {
                                    Button("Edit Rule…") { model.editing = item }
                                    Button("Show in Finder") { model.reveal(item.targetPath) }
                                    Divider()
                                    Button("Remove Rule…", role: .destructive) { model.pendingRemoval = item }
                                } label: { Image(systemName: "ellipsis") }.menuStyle(.borderlessButton).frame(width: 20).accessibilityLabel("Actions for \(item.name)")
                            }
                            Text(item.targetPath).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            HStack {
                                Label(item.isEnabled ? "VPN required" : "Rule off", systemImage: item.isEnabled ? "lock.shield" : "pause.circle")
                                    .foregroundStyle(item.isEnabled ? .teal : .secondary)
                                if item.kind == .command {
                                    Text("·")
                                    Text(model.commandIsIntegrated(item) ? "Open a new Terminal after edits" : "Command integration not installed").foregroundStyle(.secondary)
                                } else {
                                    Text("· Launch compatibility varies by app").foregroundStyle(.secondary)
                                }
                            }.font(.caption)
                        }.padding(.vertical, 12).tag(item.id)
                            .contextMenu {
                                Button("Edit Rule…") { model.editing = item }
                                Button("Remove Rule…", role: .destructive) { model.pendingRemoval = item }
                            }
                    }
                }.listStyle(.inset)
            }
            Divider()
            HStack {
                Text("\(model.enabledCount) active rules").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("Blocked when the VPN is unavailable, Iran-based, or unverified.").font(.caption).foregroundStyle(.secondary)
            }.padding(16)
        }
    }
    private var activity: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Launch activity").font(.title2.weight(.semibold))
                Text("Reset connections after reconnecting your VPN, then retry your prompt in the same terminal. Traffic contents are never logged.").foregroundStyle(.secondary)
            }.padding(.horizontal, 26).padding(.top, 26)
            if model.sessions.isEmpty {
                ContentUnavailableView("No guarded launches yet", systemImage: "waveform.path", description: Text("Launch a protected item or run an integrated command to see its status here."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.sessions) { session in
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: session.phase == "blocked" ? "hand.raised.fill" : "terminal").foregroundStyle(session.phase == "blocked" ? .orange : .secondary)
                        VStack(alignment: .leading, spacing: 5) {
                            HStack { Text(session.name).font(.headline); Text(session.phase.capitalized).font(.caption).foregroundStyle(.secondary) }
                            Text(session.message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                            Text(session.updatedAt, format: .dateTime.month().day().hour().minute().second()).font(.caption).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        if model.canReset(session) {
                            Button("Reset connections", systemImage: "arrow.triangle.2.circlepath") { model.resetConnections(session) }
                                .help("Verify the VPN again without closing this command or application.")
                        }
                    }.padding(.vertical, 8)
                }.listStyle(.inset)
            }
        }
    }
    private var settings: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Text("Settings").font(.title.weight(.semibold))
                GroupBox("Protected connection") {
                    VStack(alignment: .leading, spacing: 14) {
                        Picker("Connection", selection: $model.connectionMode) {
                            ForEach(ConnectionMode.allCases, id: \.self) { mode in Text(mode.title).tag(mode) }
                        }
                        Text("Automatic uses an explicit system HTTP or SOCKS proxy when enabled, otherwise a routed IPv4 or IPv6 tunnel. System proxy mode never falls back to a direct route.")
                            .font(.callout).foregroundStyle(.secondary)
                        if model.connectionMode == .manualProxy {
                            Picker("Proxy protocol", selection: $model.proxyKind) {
                                Text("HTTP CONNECT").tag(UpstreamProxyKind.http)
                                Text("HTTPS CONNECT (TLS to proxy)").tag(UpstreamProxyKind.https)
                                Text("SOCKS5 (remote DNS)").tag(UpstreamProxyKind.socks5)
                                Text("SOCKS4a (remote DNS)").tag(UpstreamProxyKind.socks4a)
                            }
                            HStack {
                                TextField("Host", text: $model.proxyHost).textContentType(.URL)
                                TextField("Port", text: $model.proxyPort).frame(width: 100)
                            }
                            Text("For V2Ray/Xray clients, use the local HTTP, SOCKS or mixed listening endpoint shown in that client. A router proxy can use its LAN address. Remote subscription links and VMess/VLESS URLs are not proxy endpoints.")
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                TextField("Proxy username (optional)", text: $model.proxyUsername)
                                SecureField("Proxy password (optional)", text: $model.proxyPassword)
                            }
                            if model.connectionSettings.manualProxy?.credentialID != nil {
                                Toggle("Use saved credentials for the same endpoint", isOn: $model.useSavedProxyCredentials)
                            }
                            Text("Credentials are stored in macOS Keychain. New credentials replace the saved reference. SOCKS4a uses a username only; it has no password authentication.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        HStack {
                            Button("Save and verify", systemImage: "checkmark.shield") { model.saveConnectionSettings() }
                                .buttonStyle(.borderedProminent).tint(.teal).disabled(model.isSavingConnection)
                            if model.isSavingConnection { ProgressView().controlSize(.small) }
                        }
                        Text("V2Ray/Xray through a proxy; L2TP, WireGuard, OpenVPN and other routed VPNs through a recognized tunnel. Product and configuration compatibility still needs validation. PAC/WPAD-only setups need a manual endpoint.")
                            .font(.caption).foregroundStyle(.secondary)
                    }.padding(12)
                }
                GroupBox("Startup and launches") {
                    VStack(alignment: .leading, spacing: 16) {
                        Toggle("Open VPNGuard at login", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLogin($0) }))
                        Toggle("Protection enabled", isOn: Binding(get: { model.preferences.protectionEnabled }, set: { model.setLaunchesEnabled($0) }))
                        Text("Turning protection off terminates active protected sessions and blocks new launches. It does not run commands without protection.").font(.caption).foregroundStyle(.secondary)
                    }.padding(12)
                }
                GroupBox("Terminal command integration") {
                    VStack(alignment: .leading, spacing: 14) {
                        Label(model.integrationInstalled ? "Installed for zsh" : "Not installed", systemImage: model.integrationInstalled ? "checkmark.circle" : "terminal").font(.headline)
                        Text("Adds one managed source block to .zshrc and backs up its original contents. Protected command functions take precedence over existing aliases in new zsh sessions.")
                            .foregroundStyle(.secondary).font(.callout)
                        HStack {
                            Button(model.integrationInstalled ? "Update Integration" : "Install Integration") { model.installIntegration() }.buttonStyle(.borderedProminent).tint(.teal)
                            if model.integrationInstalled { Button("Remove Integration…", role: .destructive) { removeIntegration = true } }
                        }
                        Text("For a linked .zshrc, add this line to its target manually:").font(.caption).foregroundStyle(.secondary)
                        Text(model.manualSourceLine).font(.caption.monospaced()).textSelection(.enabled).padding(10).frame(maxWidth: .infinity, alignment: .leading).background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                        Text("Open a new Terminal after setup or rule changes. Explicit absolute paths and other shells bypass command-name wrappers.").font(.caption).foregroundStyle(.secondary)
                    }.padding(12)
                }
                GroupBox("Launch folder") {
                    HStack {
                        Text(model.projectPath).font(.callout.monospaced()).lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                        Spacer()
                        Button("Choose…") { model.chooseProject() }
                    }.padding(12)
                }
                GroupBox("Uninstall VPNGuard") {
                    VStack(alignment:.leading,spacing:12) {
                        Text("Stops protected sessions, unregisters this app’s login item and legacy helper, and removes recognized VPNGuard shell integration and local data. Edited or unrecognized files are left and reported. Root-owned leftovers need manual administrator cleanup.")
                            .font(.callout).foregroundStyle(.secondary)
                        Button("Uninstall VPNGuard…",role:.destructive) { model.showingUninstall = true }
                    }.padding(12)
                }
                GroupBox("Security boundary") {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("No administrator helper required", systemImage: "person.badge.shield.checkmark").font(.headline)
                        Text("Protected processes use one private proxy. Its upstream is a verified routed IPv4/IPv6 tunnel or an explicitly selected HTTP/HTTPS/SOCKS proxy. Failed verification blocks traffic; it never falls back direct.")
                        Text("Desktop apps must launch here. Independent background services and app self-relaunch behavior are not universally covered. App compatibility needs individual validation.")
                        Text("HTTPS and secure WebSockets through HTTP CONNECT are supported. Direct child sockets, plain HTTP and UDP/QUIC remain blocked. Routed traffic uses only its verified address family.")
                        Text("The isolation tool is deprecated by Apple. If it is missing or stops working, guarded launches fail instead of running normally.")
                        Text("Exit location is a periodic external report. It cannot guarantee how a service classifies an IP address.")
                    }.font(.callout).foregroundStyle(.secondary).padding(12)
                }
            }.padding(30).frame(maxWidth: 900).frame(maxWidth: .infinity)
        }
        .confirmationDialog("Remove command integration?", isPresented: $removeIntegration, titleVisibility: .visible) {
            Button("Remove Integration", role: .destructive) { model.removeIntegration() }
            Button("Keep Integration", role: .cancel) {}
        } message: { Text("After opening a new Terminal, command names will resolve normally. Those launches may use your direct connection.") }
    }
    @State private var removeIntegration = false
    private func metric(_ title: String, value: String, symbol: String) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label(title, systemImage: symbol).font(.caption).foregroundStyle(.secondary)
                Text(value).font(.headline).textSelection(.enabled).lineLimit(1).minimumScaleFactor(0.8)
            }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    private func compactRule(_ item: ProtectedItem) -> some View {
        HStack(spacing: 12) {
            targetIcon(item).frame(width: 30, height: 30)
            VStack(alignment: .leading, spacing: 3) { Text(item.name).font(.callout.weight(.medium)); Text(item.commandName ?? "Launch through VPNGuard").font(.caption).foregroundStyle(.secondary) }
            Spacer()
            Text(item.isEnabled ? "VPN required" : "Off").font(.caption).foregroundStyle(.secondary)
            Button("Launch", systemImage: "play.fill") { model.launch(item) }.disabled(!item.isEnabled || !model.preferences.protectionEnabled)
        }
    }
    @ViewBuilder private func targetIcon(_ item: ProtectedItem) -> some View {
        if item.kind == .application {
            Image(nsImage: NSWorkspace.shared.icon(forFile: item.targetPath)).resizable().scaledToFit().accessibilityHidden(true)
        } else {
            Image(systemName: "terminal.fill").font(.title2).foregroundStyle(.secondary).accessibilityHidden(true)
        }
    }
    private func banner(_ message: String, warning: Bool, dismiss: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: warning ? "exclamationmark.triangle.fill" : "info.circle.fill").foregroundStyle(warning ? .orange : .teal)
            Text(message).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            Button("Dismiss", systemImage: "xmark") { dismiss() }.labelStyle(.iconOnly).buttonStyle(.plain)
        }.padding(12).background(warning ? Color.orange.opacity(0.09) : Color.teal.opacity(0.09))
    }
}
