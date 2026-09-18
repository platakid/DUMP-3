import SwiftUI

struct Note: Codable, Identifiable {
    let id: UUID
    var text: String
    var updated: Date
    var title: String { String(text.split(separator: "\n").first ?? "New note") }
}

@MainActor final class NotesStore: ObservableObject {
    @Published private(set) var notes: [Note] = []
    @Published var error: String?
    private let url: URL?
    init() {
        do {
            let folder = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("Notes", isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
            var excluded = folder
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            try excluded.setResourceValues(values)
            let destination = folder.appendingPathComponent("notes.json")
            let loaded: [Note]
            if FileManager.default.fileExists(atPath: destination.path) {
                loaded = try JSONDecoder().decode([Note].self, from: Data(contentsOf: destination))
            } else {
                loaded = []
            }
            url = destination
            notes = loaded
        } catch { url = nil; self.error = "Notes could not be loaded." }
    }
    func save(id: UUID, text: String) {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        var updated = notes.filter { $0.id != id }
        updated.insert(Note(id: id, text: text, updated: Date()), at: 0)
        persist(updated)
    }
    func remove(_ offsets: IndexSet) {
        var updated = notes
        updated.remove(atOffsets: offsets)
        persist(updated)
    }
    private func persist(_ updated: [Note]) {
        do {
            guard let url else { throw VaultError.storage }
            try JSONEncoder().encode(updated).write(to: url, options: [.atomic, .completeFileProtection])
            try MediaStore.protect(url)
            notes = updated
        } catch { self.error = "Your changes could not be saved." }
    }
}
