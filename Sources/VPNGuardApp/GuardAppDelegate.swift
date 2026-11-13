import AppKit
import VPNGuardCore

@MainActor final class GuardAppDelegate: NSObject, NSApplicationDelegate {
    private var powerOffObserver: NSObjectProtocol?
    private var shutdownTask: Task<Void,Never>?
    func applicationDidFinishLaunching(_ notification: Notification) {
        powerOffObserver = NSWorkspace.shared.notificationCenter.addObserver(forName:NSWorkspace.willPowerOffNotification,object:nil,queue:.main) { [weak self] _ in
            Task { @MainActor in self?.beginShutdown() }
        }
    }
    private func beginShutdown() {
        guard shutdownTask == nil else { return }
        shutdownTask = Task {
            await Task.detached(priority:.userInitiated) { SessionShutdown.stopAll() }.value
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        beginShutdown()
        Task {
            await shutdownTask?.value
            sender.reply(toApplicationShouldTerminate:true)
        }
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        // Final identity-checked fallback after the bounded graceful phase. Never
        // target unverified PIDs from pre-upgrade records or other applications.
        SessionShutdown.stopAll(grace:0)
        if let powerOffObserver { NSWorkspace.shared.notificationCenter.removeObserver(powerOffObserver) }
    }
}
