import SwiftUI
import AppKit

@main enum VPNGuardEntry {
    @MainActor static func main() async {
        if CommandLine.arguments.contains("--uninstall") {
            let code = await AppUninstallCoordinator.commandLine(preview:CommandLine.arguments.contains("--preview"))
            exit(code)
        }
        VPNGuardApp.main()
    }
}

struct VPNGuardApp: App {
    @NSApplicationDelegateAdaptor(GuardAppDelegate.self) private var appDelegate
    @State private var model = GuardModel()
    var body: some Scene {
        Window("VPNGuard", id: "main") { GuardWindow(model: model) }
            .defaultSize(width: 1120, height: 790)
            .windowResizability(.contentMinSize)
            .commands {
                CommandGroup(replacing: .newItem) { Button("Add VPN-required Item…") { model.showingAdd = true }.keyboardShortcut("n", modifiers: .command) }
                CommandMenu("Protection") {
                    Button("Verify VPN") { Task { await model.checkVPN() } }.keyboardShortcut("r", modifiers: .command).disabled(model.isChecking)
                    Button("Command Integration…") { model.section = .settings }
                }
            }
        MenuBarExtra {
            GuardMenu(model: model)
        } label: {
            Label("VPNGuard: \(model.statusTitle)", systemImage: model.statusSymbol)
        }
    }
}

struct GuardMenu: View {
    @Bindable var model: GuardModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(model.statusTitle)
        if model.vpnReady { Text("Exit: \(model.countryName)") }
        Divider()
        ForEach(model.rules.filter(\.isEnabled).prefix(8)) { item in Button("Launch \(item.name)") { model.launch(item) } }
        Divider()
        Button("Open VPNGuard") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
        Button("Verify VPN") { Task { await model.checkVPN() } }.disabled(model.isChecking)
        Button("Quit VPNGuard") { NSApp.terminate(nil) }
        Text("Command wrappers verify independently.")
    }
}
