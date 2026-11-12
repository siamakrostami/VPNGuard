import Foundation

public enum DNSHostname {
    public static func isValid(_ name: String) -> Bool {
        guard name.count <= 253, name.contains("."), !IPv4.isValid(name) else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-") && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }
}
