# Anti-Churn Design System

## Machine-Readable Tokens

```json
{
  "color": {
    "navy900": "#061A5B",
    "blue700": "#0839C7",
    "blue500": "#0A6CFF",
    "cyan400": "#22D3EE",
    "ink900": "#0F1B33",
    "slate600": "#5B6B7A",
    "surface050": "#F6F9FC",
    "white": "#FFFFFF"
  },
  "gradient": {
    "primary": "linear-gradient(135deg, #061A5B 0%, #0A6CFF 62%, #22D3EE 100%)"
  },
  "radius": {"sm": 8, "md": 16, "lg": 24},
  "spacing": {"xs": 8, "sm": 12, "md": 20, "lg": 32, "xl": 48},
  "type": {"display": "Inter, Segoe UI, Arial, sans-serif", "body": "Inter, Segoe UI, Arial, sans-serif", "mono": "JetBrains Mono, Consolas, monospace"}
}
```

## Logo System

Primary concept: one rounded loop that visibly stops before closing, paired with a cyan forward check or exit path. The silhouette must read as “break repetition, keep progress” without text.

- Icon: transparent square PNG, subject fills roughly 82-88% of width and 70-84% of height.
- Light logo: transparent mark tuned for light surfaces.
- Dark logo: transparent mark tuned for dark surfaces with brighter cyan and no glow halo.
- No background tile, drop shadow, outer ring, wordmark, tiny text, or decorative particles.
- Preserve at least 7% transparent safe space on every edge.

## Store Screenshot

One 1600 x 1000 proof-led screenshot:

- quiet off-white background;
- large headline: “Stop duplicate agent work”;
- short support line: “Reuse accepted evidence. Keep changed work moving.”;
- three decision rows: Run first action / Reuse prior evidence / Allow changed work;
- one compact receipt card with only safe example labels;
- Orbral name in a small footer;
- no fake dashboard metrics, cost claims, or busy code wall.

## Typography

- Display: 52-72 px equivalent, semibold or bold.
- Body: 22-30 px equivalent for screenshots.
- Receipt/code: 18-22 px equivalent.
- Headings use sentence case.
- Avoid all-caps paragraphs and condensed fonts.

## Layout

- Use a 12-column grid for wide screenshots.
- Left 5 columns: promise and proof bullets.
- Right 7 columns: decision/receipt demonstration.
- Keep text left-aligned and use generous whitespace.
- No text over the logo mark.

## Elevation and Shapes

- Cards use a 1 px cool-gray border and subtle 8% navy shadow only in screenshots.
- The logo itself remains flat/transparent with clean gradient volume but no external shadow.
- Rounded corners communicate controlled workflow rather than warning or restriction.

## Accessibility

- Body text contrast at least 4.5:1.
- Large text contrast at least 3:1.
- Cyan never carries meaning without a shape or label.
- Screenshot content must remain readable at 50% scale.

## Do

- Use one dominant navy/blue form and one cyan progress accent.
- Show the interrupted loop and forward path clearly.
- Make proof scannable before detail.
- Keep exact text editable and deterministic.

## Do Not

- Do not use robot heads, neural brains, stop signs, flames, coins, gauges, or infinity symbols.
- Do not place the mark on a baked white square.
- Do not use more than one cyan accent action per composition.
- Do not imply financial savings with charts or percentages.
- Do not shrink the mark into a large empty canvas.
