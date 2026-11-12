import SwiftUI
import AppKit
import VPNGuardCore

struct RuleEditor: View {
    @Bindable var model: GuardModel
    let original: ProtectedItem?
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var kind: ProtectedItemKind = .command
    @State private var path = ""
    @State private var command = ""
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            VStack(alignment: .leading, spacing: 6) {
                Text(original == nil ? "Add a VPN-required item" : "Edit rule").font(.title2.weight(.semibold))
                Text("This launch requires a verified VPN exit outside Iran.").foregroundStyle(.secondary)
            }
            Picker("Item type", selection: $kind) { Text("Terminal command").tag(ProtectedItemKind.command); Text("Application").tag(ProtectedItemKind.application) }.pickerStyle(.segmented)
            VStack(alignment: .leading, spacing: 8) {
                Text("Name").font(.callout.weight(.medium))
                TextField("For example, Claude CLI", text: $name).textFieldStyle(.roundedBorder)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text(kind == .command ? "Executable" : "App bundle").font(.callout.weight(.medium))
                HStack {
                    TextField(kind == .command ? "/Users/you/.local/bin/claude" : "/Applications/Claude.app", text: $path).textFieldStyle(.roundedBorder)
                    Button("Choose…") { browse() }
                }
            }
            if kind == .command {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Command name").font(.callout.weight(.medium))
                    TextField("claude", text: $command).textFieldStyle(.roundedBorder)
                    Text("With command integration installed, typing this name runs the VPN check first. Arguments pass through unchanged.").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Label("Launch this app through VPNGuard. Ordinary Finder launches are not intercepted. Some apps use independent services that need separate validation.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let error { Text(error).font(.callout).foregroundStyle(.red) }
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(original == nil ? "Add Rule" : "Save Rule") { save() }.buttonStyle(.borderedProminent).tint(.teal).keyboardShortcut(.defaultAction)
            }
        }.padding(28).frame(width: 560)
        .onAppear { if let original { name = original.name; kind = original.kind; path = original.targetPath; command = original.commandName ?? "" } }
    }
    private func browse() {
        let panel = NSOpenPanel(); panel.allowsMultipleSelection = false; panel.canChooseDirectories = false; panel.canChooseFiles = true
        panel.showsHiddenFiles = true; panel.treatsFilePackagesAsDirectories = false; panel.prompt = "Choose"
        panel.directoryURL = URL(fileURLWithPath: kind == .application ? "/Applications" : NSHomeDirectory() + "/.local/bin")
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
            if name.isEmpty { name = kind == .application ? url.deletingPathExtension().lastPathComponent : url.lastPathComponent }
            if command.isEmpty && kind == .command { command = url.lastPathComponent }
        }
    }
    private func save() {
        do {
            let item = try ProtectedItem(id: original?.id ?? UUID(), name: name.trimmingCharacters(in: .whitespacesAndNewlines), kind: kind,
                                         targetPath: path.trimmingCharacters(in: .whitespacesAndNewlines), commandName: kind == .command ? command : nil,
                                         isEnabled: original?.isEnabled ?? true, addedAt: original?.addedAt ?? Date())
            if kind == .command && !FileManager.default.isExecutableFile(atPath: item.targetPath) { throw GuardError.invalid("Choose an existing executable file.") }
            if kind == .application && Bundle(path: item.targetPath)?.executableURL == nil { throw GuardError.invalid("Choose an app bundle with an executable.") }
            var items = model.rules.filter { $0.id != item.id }; items.append(item); try GuardPreferences.validate(items: items)
            model.save(item)
            if model.error == nil { dismiss() } else { error = model.error }
        } catch { self.error = error.localizedDescription }
    }
}
