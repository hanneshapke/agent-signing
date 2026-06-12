import SwiftUI

struct MealDetailView: View {
    @EnvironmentObject private var store: MealStore
    @Environment(\.dismiss) private var dismiss

    let meal: Meal

    var body: some View {
        ZStack {
            Theme.paper.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    photo
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: meal.type.label)
                        Text(meal.name)
                            .font(Theme.serif(34))
                            .foregroundStyle(Theme.ink)
                    }
                    details
                    deleteButton
                }
                .padding(24)
            }
        }
        .toolbar(.visible, for: .navigationBar)
        .toolbarBackground(Theme.paper, for: .navigationBar)
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private var photo: some View {
        if let image = store.image(for: meal) {
            Image(uiImage: image)
                .resizable()
                .scaledToFill()
                .frame(maxWidth: .infinity)
                .frame(height: 260)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .shadow(color: .black.opacity(0.12), radius: 18, y: 10)
        } else {
            RoundedRectangle(cornerRadius: 10)
                .fill(Theme.cream)
                .frame(height: 160)
                .overlay(
                    VStack(spacing: 8) {
                        Image(systemName: "fork.knife")
                            .font(.system(size: 24))
                        Text("NO PHOTO")
                            .font(Theme.mono(10, weight: .medium))
                            .kerning(1.2)
                    }
                    .foregroundStyle(Theme.slate)
                )
        }
    }

    private var details: some View {
        InkCard {
            InkCardRow(key: "logged_at", value: meal.date.formatted(
                date: .abbreviated, time: .shortened
            ))
            InkCardRow(key: "type", value: meal.type.label.lowercased())
            InkCardRow(key: "calories", value: "\(meal.calories) kcal")
            InkCardRow(
                key: "photo",
                value: meal.imageFilename != nil ? "✓ attached" : "—"
            )
        }
    }

    private var deleteButton: some View {
        Button {
            store.delete(meal)
            dismiss()
        } label: {
            Text("DELETE ENTRY")
                .foregroundStyle(Theme.rust)
        }
        .buttonStyle(SecondaryButtonStyle())
        .padding(.top, 8)
    }
}

#Preview {
    NavigationStack {
        MealDetailView(meal: Meal(
            name: "Avocado toast",
            calories: 420,
            type: .breakfast,
            date: .now
        ))
        .environmentObject(MealStore())
    }
}
