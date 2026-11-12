import Foundation

public enum CommandLauncher {
    /// The directory is captured per launch. Never evaluate a user-selected path as shell syntax.
    public static func script(runner: String, ruleID: UUID, config: String, directory: URL) -> String {
        """
        #!/bin/zsh
        cd -- \(ShellArgument.quote(directory.path)) || exit 1
        \(ShellArgument.quote(runner)) --rule \(ShellArgument.quote(ruleID.uuidString)) --config \(ShellArgument.quote(config)) --
        result=$?
        if [[ $result -ne 0 ]]; then printf '\\nVPNGuard stopped this launch (status %s).\\n' "$result"; fi
        exit $result

        """
    }
}
