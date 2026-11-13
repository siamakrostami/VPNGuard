import AppKit
import Foundation
import ServiceManagement
import VPNGuardCore

@MainActor enum AppUninstallCoordinator {
    static func perform(preview: Bool) async throws -> UninstallReport {
        let plan = UninstallPlan(home:FileManager.default.homeDirectoryForCurrentUser)
        let proposed = try plan.preview() // Validate before unregistration or deletion.
        if preview { return proposed }
        await Task.detached(priority:.userInitiated) { SessionShutdown.stopAll() }.value
        let login = SMAppService.mainApp
        if login.status == .enabled || login.status == .requiresApproval { try await login.unregister() }
        let legacy = SMAppService.daemon(plistName:"com.siamak.VPNGuard.helper.plist")
        if legacy.status == .enabled || legacy.status == .requiresApproval { try await legacy.unregister() }
        // New builds intentionally ship no legacy daemon descriptor/executable.
        // .notFound cannot prove stale registrations from old copies were removed.
        // Never pretend that a per-bundle status query enumerates stale BTM entries
        // from every historical copy. No global BTM reset or other app is touched.
        var report = try plan.execute()
        report.left.append("Historical VPNGuard background entries from other bundle copies cannot be enumerated or verified removed by this per-bundle API. Review Login Items manually if entries remain.")
        report.left.append("VPNGuard app bundles and source backups are left in place. Move only the VPNGuard copies you no longer need to Trash after quitting.")
        return report
    }
    static func commandLine(preview: Bool) async -> Int32 {
        do {
            let report = try await perform(preview:preview)
            print(preview ? "VPNGuard uninstall preview. No services or files were changed." : "VPNGuard uninstall results:")
            for path in report.removed { print((preview ? "Would remove: " : "Removed: ") + path) }
            for path in report.left { print("Left: " + path) }
            print("Manual administrator cleanup, shown only; nothing below was executed:")
            for command in report.manualCommands { print(command) }
            print("This uninstaller never changes another VPN client's files, profiles, services, or firewall rules.")
            return 0
        } catch {
            fputs("VPNGuard uninstall stopped: \(error.localizedDescription)\nNo automatic privileged cleanup was attempted.\n",stderr)
            return 1
        }
    }
    static func inApp() async throws {
        let report = try await perform(preview:false)
        let alert = NSAlert()
        alert.messageText = "VPNGuard uninstall results"
        var lines = ["Removed:"]
        lines.append(contentsOf: report.removed)
        lines.append("\nLeft:")
        lines.append(contentsOf: report.left)
        lines.append("\nManual administrator commands (not executed):")
        lines.append(contentsOf: report.manualCommands)
        alert.informativeText = lines.joined(separator:"\n")
        alert.addButton(withTitle:"Quit VPNGuard")
        alert.runModal()
        NSApp.terminate(nil)
    }
}
