import SwiftUI
import AVKit
import Photos
import UniformTypeIdentifiers

struct VaultView: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var preview: MediaPreview
    @State private var deleteCandidate: MediaInfo?
    init(model: AppModel) { self.model = model; self.preview = model.preview }
    var body: some View {
        NavigationStack {
            List {
                if model.media.isEmpty {
                    ContentUnavailableView("Your space, kept private.", systemImage: "square.stack", description: Text("Import a local photo or video to begin."))
                        .listRowBackground(Color.clear)
                }
                ForEach(model.media) { item in
                    Button { Task { await model.show(item) } } label: {
                        HStack(spacing: 16) {
                            Image(systemName: icon(item)).font(.title2).frame(width: 44, height: 50).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.name).font(.headline).lineLimit(1)
                                Text(item.importedAt, style: .date).font(.caption).foregroundStyle(.secondary)
                            }
                        }.padding(.vertical, 7)
                    }.swipeActions { Button("Delete", role: .destructive) { deleteCandidate = item } }
                        .swipeActions(edge: .leading) {
                            if UTType(item.typeIdentifier)?.conforms(to: .image) == true || UTType(item.typeIdentifier)?.conforms(to: .movie) == true {
                                Button("Export", systemImage: "square.and.arrow.up") { model.requestExport(item) }.tint(.blue)
                            }
                        }
                        .contextMenu {
                            if UTType(item.typeIdentifier)?.conforms(to: .image) == true || UTType(item.typeIdentifier)?.conforms(to: .movie) == true {
                                Button("Export to Photos", systemImage: "square.and.arrow.up") { model.requestExport(item) }
                            }
                        }
                }
                if model.busy { HStack { ProgressView(); Text("Working…").foregroundStyle(.secondary) } }
            }.navigationTitle("DUMP").listStyle(.insetGrouped)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) { Button { model.lock() } label: { Image(systemName: "lock") }.accessibilityLabel("Lock") }
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        Button { model.showingSettings = true } label: { Image(systemName: "slider.horizontal.3") }.accessibilityLabel("Settings")
                        Button { Task { await model.openLibrary() } } label: { Image(systemName: "plus") }.accessibilityLabel("Import from Photos").disabled(model.busy)
                    }
                }
                .sheet(isPresented: $model.showingLibrary) { PhotoLibraryView(model: model) }
                .sheet(isPresented: $model.showingSettings) { SettingsView(model: model) }
                .sheet(item: $model.exportCandidate) { item in ExportConfirmationView(model: model, item: item) }
                .fullScreenCover(isPresented: Binding(get: { preview.item != nil }, set: { if !$0 { preview.clear() } })) { PreviewView(preview: preview) }
                .confirmationDialog("Delete the original from Photos?", isPresented: $model.askToDeleteOriginal, titleVisibility: .visible) {
                    Button("Delete from Photos", role: .destructive) { Task { await model.deleteOriginal() } }
                    Button("Keep original", role: .cancel) { model.importedAsset = nil }
                } message: {
                    Text("All resources were encrypted and verified. Photos deletion moves the original to Recently Deleted for up to 30 days. This is an iOS platform limitation, not a DUMP limitation. Deletion does not guarantee secure erasure. If your Photos library uses iCloud Photos, deletion may also sync to your other devices.")
                }
                .confirmationDialog("Delete this item from DUMP?", isPresented: Binding(get: { deleteCandidate != nil }, set: { if !$0 { deleteCandidate = nil } }), titleVisibility: .visible) {
                    Button("Delete encrypted item", role: .destructive) {
                        if let item = deleteCandidate { Task { await model.deleteMedia(item) } }
                        deleteCandidate = nil
                    }
                } message: { Text("This removes the encrypted copy from this device. It cannot be undone.") }
        }
    }
    private func icon(_ item: MediaInfo) -> String {
        if UTType(item.typeIdentifier)?.conforms(to: .movie) == true { return "play.rectangle" }
        if UTType(item.typeIdentifier)?.conforms(to: .image) == true { return "photo" }
        return "doc"
    }
}

struct ExportConfirmationView: View {
    @ObservedObject var model: AppModel
    let item: MediaInfo
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Image(systemName: "square.and.arrow.up").font(.largeTitle)
                    Text("Export to Photos").font(.largeTitle.bold())
                    Text(item.name).font(.headline)
                    Text("Exporting removes this file's protection. Once saved outside DUMP, it is no longer encrypted and is subject to normal iOS storage/backup behavior.")
                    Text("Your encrypted copy in DUMP will remain unchanged. If iCloud Photos is enabled, the exported copy may sync to your other devices.")
                    Text("Export uses a temporary unencrypted file. DUMP attempts to overwrite and delete it when Photos finishes. App termination or power loss can leave it behind, and physical secure erasure cannot be guaranteed.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Confirm export to Photos") { Task { await model.confirmExport() } }.buttonStyle(PrimaryButton())
                    Button("Cancel") { model.exportCandidate = nil }.frame(maxWidth: .infinity)
                }.padding(28)
            }.navigationBarTitleDisplayMode(.inline)
        }
    }
}

struct PhotoLibraryView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Only media already on this device can be imported. DUMP does not download from iCloud.").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(model.photos, id: \.localIdentifier) { asset in
                    Button { dismiss(); Task { await model.importAsset(asset) } } label: {
                        HStack {
                            Image(systemName: asset.mediaType == .video ? "video" : "photo")
                            VStack(alignment: .leading) {
                                Text(asset.mediaType == .video ? "Video" : "Photo")
                                if let date = asset.creationDate { Text(date, style: .date).font(.caption).foregroundStyle(.secondary) }
                                Text("\(asset.pixelWidth) × \(asset.pixelHeight)").font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("Import").font(.subheadline)
                        }
                    }
                }
            }.navigationTitle("Import").toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

struct PreviewView: View {
    @ObservedObject var preview: MediaPreview
    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()
            if let image = preview.image { Image(uiImage: image).resizable().scaledToFit().frame(maxWidth: .infinity, maxHeight: .infinity) }
            if let player = preview.player { VideoPlayer(player: player).ignoresSafeArea(edges: .bottom) }
            Button { preview.clear() } label: { Image(systemName: "xmark").font(.headline).padding(14).background(.regularMaterial, in: Circle()) }
                .padding(20).accessibilityLabel("Close preview")
        }.onDisappear { preview.clear() }
    }
}

struct SettingsView: View {
    @ObservedObject var model: AppModel
    @State private var old = ""
    @State private var new = ""
    @State private var confirmation = ""
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section("Change passcode") {
                    SecureField("Current passcode", text: $old)
                    SecureField("New passcode", text: $new)
                    SecureField("Confirm new passcode", text: $confirmation)
                    Text("At least 8 characters, including a number or symbol.").font(.footnote).foregroundStyle(.secondary)
                    Button("Change passcode") {
                        let o = old, n = new, c = confirmation
                        old = ""; new = ""; confirmation = ""
                        Task { await model.changePasscode(old: o, new: n, confirmation: c) }
                    }.disabled(model.busy || old.isEmpty || new.isEmpty || confirmation.isEmpty)
                }
                Section {
                    Text("Stored only on this device. No account, server, cloud sync, or vault backup. There is no passcode recovery.")
                    Text("Removing the device passcode destroys access to the protected key. DUMP cannot recover those files.")
                }.font(.footnote).foregroundStyle(.secondary)
            }.textContentType(.none).textInputAutocapitalization(.never).autocorrectionDisabled()
                .navigationTitle("Settings").toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }.onDisappear { old = ""; new = ""; confirmation = "" }
    }
}
