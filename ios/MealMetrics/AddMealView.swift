import PhotosUI
import SwiftUI

struct AddMealView: View {
    @EnvironmentObject private var store: MealStore
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var calories = ""
    @State private var type: MealType = .lunch
    @State private var pickerItem: PhotosPickerItem?
    @State private var image: UIImage?
    @State private var showCamera = false

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
            && Int(calories) != nil
    }

    var body: some View {
        ZStack {
            Theme.paper.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 26) {
                    header
                    photoSection
                    field(label: "Meal") {
                        TextField("e.g. Avocado toast", text: $name)
                            .font(Theme.sans(15))
                    }
                    field(label: "Calories") {
                        TextField("e.g. 420", text: $calories)
                            .font(Theme.sans(15))
                            .keyboardType(.numberPad)
                    }
                    typeSection
                    saveButton
                }
                .padding(24)
            }
        }
        .onChange(of: pickerItem) { _, newItem in
            Task {
                if let data = try? await newItem?.loadTransferable(type: Data.self),
                   let loaded = UIImage(data: data) {
                    image = loaded
                }
            }
        }
        .fullScreenCover(isPresented: $showCamera) {
            CameraPicker { image = $0 }
                .ignoresSafeArea()
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel(text: "New Entry")
                (
                    Text("Log a ")
                    + Text("meal.").italic().foregroundColor(Theme.rust)
                )
                .font(Theme.serif(32))
                .foregroundColor(Theme.ink)
            }
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.slate)
                    .frame(width: 32, height: 32)
                    .overlay(Circle().strokeBorder(Theme.ghost, lineWidth: 1))
            }
        }
    }

    // MARK: - Photo

    @ViewBuilder
    private var photoSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "Photo", color: Theme.slate)
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(maxWidth: .infinity)
                    .frame(height: 220)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(alignment: .topTrailing) {
                        Button {
                            self.image = nil
                            pickerItem = nil
                        } label: {
                            Text("REMOVE")
                                .font(Theme.mono(10, weight: .medium))
                                .kerning(1)
                                .foregroundStyle(Theme.paper)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Theme.ink.opacity(0.75))
                                .clipShape(Capsule())
                        }
                        .padding(10)
                    }
            } else {
                HStack(spacing: 10) {
                    PhotosPicker(selection: $pickerItem, matching: .images) {
                        photoOption(icon: "photo.on.rectangle", label: "Choose photo")
                    }
                    if UIImagePickerController.isSourceTypeAvailable(.camera) {
                        Button {
                            showCamera = true
                        } label: {
                            photoOption(icon: "camera", label: "Take photo")
                        }
                    }
                }
            }
        }
    }

    private func photoOption(icon: String, label: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 20))
                .foregroundStyle(Theme.sage)
            Text(label.uppercased())
                .font(Theme.mono(10, weight: .medium))
                .kerning(1)
                .foregroundStyle(Theme.slate)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 26)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(
                    Theme.slate.opacity(0.3),
                    style: StrokeStyle(lineWidth: 1, dash: [5, 4])
                )
        )
        .contentShape(Rectangle())
    }

    // MARK: - Fields

    private func field(label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: label, color: Theme.slate)
            content()
                .padding(14)
                .background(Color.white.opacity(0.6))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(Theme.ghost, lineWidth: 1)
                )
        }
    }

    private var typeSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(text: "Type", color: Theme.slate)
            HStack(spacing: 8) {
                ForEach(MealType.allCases) { mealType in
                    Button {
                        type = mealType
                    } label: {
                        Text(mealType.label.uppercased())
                            .font(Theme.mono(10, weight: .medium))
                            .kerning(0.8)
                            .padding(.horizontal, 11)
                            .padding(.vertical, 9)
                            .background(type == mealType ? Theme.ink : Color.clear)
                            .foregroundStyle(type == mealType ? Theme.paper : Theme.slate)
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                            .overlay(
                                RoundedRectangle(cornerRadius: 4)
                                    .strokeBorder(
                                        type == mealType ? Theme.ink : Theme.ghost,
                                        lineWidth: 1
                                    )
                            )
                    }
                }
            }
        }
    }

    private var saveButton: some View {
        Button {
            store.add(
                name: name.trimmingCharacters(in: .whitespaces),
                calories: Int(calories) ?? 0,
                type: type,
                image: image
            )
            dismiss()
        } label: {
            Text("SAVE MEAL")
        }
        .buttonStyle(PrimaryButtonStyle())
        .disabled(!canSave)
        .opacity(canSave ? 1 : 0.4)
        .padding(.top, 8)
    }
}

/// UIKit camera bridge — SwiftUI has no native camera capture view.
struct CameraPicker: UIViewControllerRepresentable {
    var onImage: (UIImage) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIImagePickerController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UIImagePickerControllerDelegate,
        UINavigationControllerDelegate {
        let parent: CameraPicker

        init(_ parent: CameraPicker) { self.parent = parent }

        func imagePickerController(
            _ picker: UIImagePickerController,
            didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
        ) {
            if let image = info[.originalImage] as? UIImage {
                parent.onImage(image)
            }
            parent.dismiss()
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            parent.dismiss()
        }
    }
}

#Preview {
    AddMealView()
        .environmentObject(MealStore())
}
