import Foundation

public enum SessionPolicy {
    public static func permits(ruleID: UUID, settings: GuardPreferences) -> Bool {
        settings.protectionEnabled && settings.items.contains { $0.id == ruleID && $0.isEnabled }
    }
}

/// Rechecks the actual saved rule throughout checking and running phases. Removal,
/// exclusion, global disable, or an unreadable file revokes the session once.
public final class SessionPolicyWatcher: @unchecked Sendable {
    private let lock = NSLock()
    private let ruleID:UUID
    private let store:RuleStore
    private let onRevoked:@Sendable () -> Void
    private var revoked = false
    private var timer:DispatchSourceTimer?
    public init(ruleID:UUID,store:RuleStore,onRevoked:@escaping @Sendable ()->Void) {
        self.ruleID = ruleID;self.store = store;self.onRevoked = onRevoked
    }
    deinit { stop() }
    public func checkNow() {
        let permitted = (try? store.load()).map { SessionPolicy.permits(ruleID:ruleID,settings:$0) } ?? false
        guard !permitted else { return }
        lock.lock();let notify = !revoked;revoked = true;lock.unlock()
        if notify { onRevoked() }
    }
    public func start() {
        lock.lock();defer{lock.unlock()}
        guard timer == nil else{return}
        let source = DispatchSource.makeTimerSource(queue:DispatchQueue(label:"VPNGuard.session.policy"))
        source.schedule(deadline:.now(),repeating:1)
        source.setEventHandler { [weak self] in self?.checkNow() }
        timer = source;source.resume()
    }
    public func stop() { lock.lock();timer?.cancel();timer = nil;lock.unlock() }
}
