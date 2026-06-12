import SwiftUI

/// Uppercase mono section label, like the site's `.section-label`.
struct SectionLabel: View {
    let text: String
    var color: Color = Theme.sage

    var body: some View {
        Text(text.uppercased())
            .font(Theme.mono(11, weight: .medium))
            .kerning(1.5)
            .foregroundStyle(color)
    }
}

/// Cream stat card with a serif figure, like the site's `.step` cards.
struct MetricCard: View {
    let value: String
    var unit: String?
    let title: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(value)
                    .font(Theme.serif(34))
                    .foregroundStyle(Theme.ink)
                if let unit {
                    Text(unit)
                        .font(Theme.mono(11))
                        .foregroundStyle(Theme.slate)
                }
            }
            Text(title.uppercased())
                .font(Theme.mono(10, weight: .medium))
                .kerning(1.2)
                .foregroundStyle(Theme.slate)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(Theme.cream)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Theme.ghost, lineWidth: 1)
        )
    }
}

/// Ink button with mono label, like the site's `.btn-primary`
/// (turns rust when pressed, as the site does on hover).
struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.mono(13, weight: .medium))
            .kerning(1)
            .foregroundStyle(Theme.paper)
            .padding(.vertical, 15)
            .frame(maxWidth: .infinity)
            .background(configuration.isPressed ? Theme.rust : Theme.ink)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

/// Outlined mono button, like the site's `.btn-secondary`.
struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.mono(13))
            .foregroundStyle(configuration.isPressed ? Theme.ink : Theme.slate)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(
                        Theme.slate.opacity(configuration.isPressed ? 0.6 : 0.25),
                        lineWidth: 1
                    )
            )
    }
}

/// One `key  value` line inside an ink card, like the site's `.sig-line`.
struct InkCardRow: View {
    let key: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(key)
                .font(Theme.mono(12))
                .foregroundStyle(Theme.sageLight)
            Spacer()
            Text(value)
                .font(Theme.mono(12))
                .foregroundStyle(Theme.paper)
                .lineLimit(1)
                .truncationMode(.tail)
        }
    }
}

/// Dark card with the sage→rust top stripe, like the site's `.sig-card`.
struct InkCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(20)
        .background(Theme.ink)
        .overlay(alignment: .top) {
            LinearGradient(
                colors: [Theme.sage, Theme.rust],
                startPoint: .leading,
                endPoint: .trailing
            )
            .frame(height: 3)
        }
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .shadow(color: .black.opacity(0.12), radius: 18, y: 10)
    }
}
