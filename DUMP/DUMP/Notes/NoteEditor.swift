import SwiftUI

struct NoteTextView: UIViewRepresentable {
    @Binding var text: String
    let isNew: Bool
    let reveal: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.backgroundColor = .clear
        view.textContainerInset = .init(top: 24, left: 18, bottom: 24, right: 18)
        view.autocorrectionType = .no
        view.spellCheckingType = .no
        view.autocapitalizationType = .none
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.text = text
        return view
    }
    func updateUIView(_ view: UITextView, context: Context) {
        context.coordinator.parent = self
        if view.text != text { view.text = text }
    }
    static func triggers(isNew: Bool, current: String, range: NSRange, replacement: String) -> Bool {
        isNew && current == "DUMPunlock0715" && replacement == " " && range.length == 0 && range.location == (current as NSString).length
    }
    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: NoteTextView
        init(_ parent: NoteTextView) { self.parent = parent }
        func textViewDidChange(_ view: UITextView) { parent.text = view.text }
        func textView(_ view: UITextView, shouldChangeTextIn range: NSRange, replacementText text: String) -> Bool {
            if NoteTextView.triggers(isNew: parent.isNew, current: view.text, range: range, replacement: text) {
                view.text = ""; parent.text = ""
                view.resignFirstResponder()
                parent.reveal()
                return false
            }
            return true
        }
    }
}

struct DraftNote: Identifiable {
    let id: UUID
    let isNew: Bool
    let text: String
}

struct NotesView: View {
    @ObservedObject var store: NotesStore
    let reveal: () -> Void
    @State private var draft: DraftNote?
    var body: some View {
        NavigationStack {
            List {
                if store.notes.isEmpty {
                    ContentUnavailableView("A little space for everything.", systemImage: "note.text", description: Text("Ideas, lists, and things to remember."))
                        .listRowBackground(Color.clear)
                }
                ForEach(store.notes) { note in
                    Button { draft = DraftNote(id: note.id, isNew: false, text: note.text) } label: {
                        VStack(alignment: .leading, spacing: 7) {
                            Text(note.title).font(.headline).lineLimit(1).foregroundStyle(.primary)
                            Text(note.updated, style: .date).font(.caption).foregroundStyle(.secondary)
                        }.padding(.vertical, 10)
                    }
                }.onDelete(perform: store.remove)
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Note Dump")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { draft = DraftNote(id: UUID(), isNew: true, text: "") } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel("New note")
                }
            }
            .sheet(item: $draft) { note in
                NoteEditor(draft: note, save: { store.save(id: note.id, text: $0); draft = nil }, reveal: { draft = nil; reveal() })
            }
            .alert("Notes", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
                Button("OK") { store.error = nil }
            } message: { Text(store.error ?? "") }
        }
    }
}

struct NoteEditor: View {
    let draft: DraftNote
    let save: (String) -> Void
    let reveal: () -> Void
    @State private var text: String
    @Environment(\.dismiss) private var dismiss
    init(draft: DraftNote, save: @escaping (String) -> Void, reveal: @escaping () -> Void) {
        self.draft = draft; self.save = save; self.reveal = reveal
        _text = State(initialValue: draft.text)
    }
    var body: some View {
        NavigationStack {
            NoteTextView(text: $text, isNew: draft.isNew, reveal: reveal)
                .navigationTitle(draft.isNew ? "New Note" : "Note").navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { text = ""; dismiss() } }
                    ToolbarItem(placement: .confirmationAction) { Button("Done") { save(text); text = "" } }
                }
        }.interactiveDismissDisabled()
    }
}
