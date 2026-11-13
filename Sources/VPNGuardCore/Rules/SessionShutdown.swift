import Foundation

public enum SessionShutdown {
    public static func records(storeURL: URL = RuleStore().url) -> [GuardSessionRecord] {
        let folder = storeURL.deletingLastPathComponent().appendingPathComponent("Sessions",isDirectory:true)
        let files = (try? FileManager.default.contentsOfDirectory(at:folder,includingPropertiesForKeys:nil,options:.skipsHiddenFiles)) ?? []
        return files.filter { $0.pathExtension == "json" }.compactMap { url in
            guard let data = try? Data(contentsOf:url),data.count < 100_000,
                  let record = try? JSONDecoder().decode(GuardSessionRecord.self,from:data),record.phase != "ended" else { return nil }
            return record
        }
    }
    public static func stopAll(storeURL:URL = RuleStore().url,grace:TimeInterval = 5) {
        let sessions = records(storeURL:storeURL)
        SessionLifecycle.terminate(sessions.compactMap(\.processSession),runners:sessions.compactMap(\.runnerIdentity),grace:grace)
    }
}
