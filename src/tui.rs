use crate::BrainWaveParser;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style},
    symbols,
    text::Line,
    widgets::{
        Axis, Bar, BarChart, BarGroup, Block, Borders, Chart, Clear, Dataset, GraphType, List,
        ListItem, ListState, Paragraph,
    },
};
use std::sync::atomic::Ordering;

pub fn render_dashboard(f: &mut Frame, parser: &BrainWaveParser) {
    let mut constraints = vec![
        Constraint::Length(3),  // Info
        Constraint::Length(8),  // Raw EEG Wave
        Constraint::Min(10),    // Attention & Meditation
        Constraint::Length(10), // Bands Oscilloscope
        Constraint::Length(10), // EEG Bands (Bar Chart)
    ];

    if parser.show_debug {
        constraints.push(Constraint::Length(10)); // MoQ Debug
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    // Header / Info Block. A Bluetooth headset that is not streaming says so first — the signal
    // fields below describe a headset that is.
    let headset_note = match &parser.headset_state {
        Some(crate::HeadsetState::Streaming) | None => None,
        Some(crate::HeadsetState::Missing) => Some(if cfg!(target_os = "macos") {
            "No headset — M › Headset".to_string()
        } else {
            "No headset — name its port: neuralkit <port>".to_string()
        }),
        Some(_) => {
            let name = parser.headset.as_ref().map_or("Headset", |(n, _)| n.as_str());
            Some(format!("{name} {}", headset_label(parser)))
        }
    };
    let status = if parser.is_paused {
        "PAUSED"
    } else if let Some(note) = &headset_note {
        note.as_str()
    } else if parser.last_poor_signal == 0 {
        "Connected (Good Signal)"
    } else if parser.last_poor_signal == 200 {
        "Poor Signal (Off-head)"
    } else {
        "Connecting..."
    };

    let info_block = Block::default().borders(Borders::ALL).title("");
    let info_area = chunks[0];
    f.render_widget(info_block, info_area);

    let info_inner = info_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });
    let info_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(30)])
        .split(info_inner);

    let moq_status = parser
        .moq_status
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let latency_text = if parser.is_subscriber {
        let connect_rtt = parser
            .connect_rtt_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        format!(
            " | EEG-LAT: {:>3}ms | JIT: {:>3}ms | RTT: {:>3}ms",
            parser.last_latency_ms, parser.jitter_ms, connect_rtt
        )
    } else {
        "".to_string()
    };

    let status_text = Paragraph::new(format!(
        " Neuralkit v0.0.1 | Status: {} | Signal Loss: {} | MoQ: {}{}",
        status, parser.last_poor_signal, moq_status, latency_text
    ));
    f.render_widget(status_text, info_layout[0]);

    let help_line = if parser.is_subscriber {
        "[Q] Quit  [P] Pause  [D] Debug  [-/+] Zoom  [M] Menu  [R] Reconnect"
    } else {
        "[Q] Quit  [P] Pause  [D] Debug  [-/+] Zoom  [M] Menu"
    };
    let help_text = Paragraph::new(help_line)
        .alignment(ratatui::layout::Alignment::Right)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help_text, info_layout[1]);

    // Raw EEG Wave — plot only the last `raw_window` samples (horizontal zoom),
    // re-indexed from 0 so they fill the widget width.
    let raw_skip = parser.raw_history.len().saturating_sub(parser.raw_window);
    let raw_points: Vec<(f64, f64)> = parser
        .raw_history
        .iter()
        .skip(raw_skip)
        .enumerate()
        .map(|(i, &v)| (i as f64, v as f64))
        .collect();

    // Auto-scale the Y axis to the displayed samples so the wave fills the widget
    // vertically instead of sitting flat inside the fixed ±2048 ADC range (real
    // EEG amplitude is a small fraction of that).
    let (mut y_lo, mut y_hi) = (f64::INFINITY, f64::NEG_INFINITY);
    for &(_, y) in &raw_points {
        y_lo = y_lo.min(y);
        y_hi = y_hi.max(y);
    }
    if !y_lo.is_finite() || !y_hi.is_finite() {
        y_lo = -2048.0;
        y_hi = 2047.0;
    }
    let y_pad = ((y_hi - y_lo) * 0.15).max(16.0);
    let (y_lo, y_hi) = (y_lo - y_pad, y_hi + y_pad);
    let y_mid = (y_lo + y_hi) / 2.0;

    let raw_dataset = Dataset::default()
        .name("Raw EEG")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::White))
        .data(&raw_points);

    let raw_chart = Chart::new(vec![raw_dataset])
        .block(
            Block::default()
                .title(format!(
                    "Raw EEG Wave (512Hz)  ·  zoom: {} samples ({}ms)  [-/+]",
                    parser.raw_window,
                    parser.raw_window * 1000 / 512
                ))
                .borders(Borders::ALL),
        )
        .x_axis(Axis::default().bounds([0.0, parser.raw_window as f64]))
        .y_axis(Axis::default().bounds([y_lo, y_hi]).labels(vec![
            Line::from(format!("{:.0}", y_lo)),
            Line::from(format!("{:.0}", y_mid)),
            Line::from(format!("{:.0}", y_hi)),
        ]));
    f.render_widget(raw_chart, chunks[1]);

    // Bands Oscilloscope
    let colors = [
        Color::Red,
        Color::Yellow,
        Color::Green,
        Color::Blue,
        Color::Magenta,
    ];
    let label_names = ["Delta", "Theta", "Alpha", "Beta", "Gamma"];

    // Pre-collect points for each band to avoid lifetime issues
    let mut bands_points: Vec<Vec<(f64, f64)>> = vec![Vec::new(); 5];
    for (i, b) in parser.bands_history.iter().enumerate() {
        bands_points[0].push((i as f64, b.delta as f64));
        bands_points[1].push((i as f64, b.theta as f64));
        bands_points[2].push((i as f64, b.alpha as f64));
        bands_points[3].push((i as f64, b.beta as f64));
        bands_points[4].push((i as f64, b.gamma as f64));
    }

    let band_datasets: Vec<Dataset> = (0..5)
        .map(|i| {
            Dataset::default()
                .name(label_names[i])
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(colors[i]))
                .data(&bands_points[i])
        })
        .collect();

    let bands_chart = Chart::new(band_datasets)
        .block(
            Block::default()
                .title("Bands Oscilloscope (%)")
                .borders(Borders::ALL),
        )
        .x_axis(Axis::default().bounds([0.0, 100.0]))
        .y_axis(Axis::default().bounds([0.0, 1.0]).labels(vec![
            Line::from("0%"),
            Line::from("50%"),
            Line::from("100%"),
        ]));
    f.render_widget(bands_chart, chunks[3]);

    // Main Graphs (Attention & Meditation)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[2]);

    let current_attention = parser.attention_history.back().cloned().unwrap_or(0);
    let attention_points: Vec<(f64, f64)> = parser
        .attention_history
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v as f64))
        .collect();

    let attention_dataset = Dataset::default()
        .name(" Attention ")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Yellow))
        .data(&attention_points);

    let attention_chart = Chart::new(vec![attention_dataset])
        .block(
            Block::default()
                .title(format!("Attention: {} (eSense)", current_attention))
                .borders(Borders::ALL),
        )
        .x_axis(Axis::default().bounds([0.0, 100.0]))
        .y_axis(Axis::default().bounds([0.0, 100.0]).labels(vec![
            Line::from("0"),
            Line::from("50"),
            Line::from("100"),
        ]));
    f.render_widget(attention_chart, body_chunks[0]);

    let current_meditation = parser.meditation_history.back().cloned().unwrap_or(0);
    let meditation_points: Vec<(f64, f64)> = parser
        .meditation_history
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v as f64))
        .collect();

    let meditation_dataset = Dataset::default()
        .name(" Meditation ")
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&meditation_points);

    let meditation_chart = Chart::new(vec![meditation_dataset])
        .block(
            Block::default()
                .title(format!("Meditation: {} (eSense)", current_meditation))
                .borders(Borders::ALL),
        )
        .x_axis(Axis::default().bounds([0.0, 100.0]))
        .y_axis(Axis::default().bounds([0.0, 100.0]).labels(vec![
            Line::from("0"),
            Line::from("50"),
            Line::from("100"),
        ]));
    f.render_widget(meditation_chart, body_chunks[1]);

    // EEG Bands
    if parser.last_band_data.is_some() {
        // Draw the eased/smoothed heights (updated in the render loop); the gate
        // still keys off real data having arrived.
        let bands = &parser.shown_bands;
        let eeg_block = Block::default()
            .title("EEG Power Bands (%)")
            .borders(Borders::ALL);
        let eeg_area = chunks[4];
        f.render_widget(eeg_block, eeg_area);

        let eeg_inner = eeg_area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let eeg_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),    // Bars
                Constraint::Length(2), // Labels + Values
            ])
            .split(eeg_inner);

        let colors = [
            Color::Red,
            Color::Yellow,
            Color::Green,
            Color::Blue,
            Color::Magenta,
        ];
        let label_names = ["Delta", "Theta", "Alpha", "Beta", "Gamma"];
        let raw_values = [
            bands.delta,
            bands.theta,
            bands.alpha,
            bands.beta,
            bands.gamma,
        ];

        let mut bars = Vec::new();
        for i in 0..5 {
            bars.push(
                Bar::default()
                    .value((raw_values[i] * 100.0) as u64)
                    .style(Style::default().fg(colors[i]))
                    .text_value("".to_string()),
            );
        }

        let num_bars = bars.len() as u16;
        let bar_width = (eeg_inner.width / num_bars).saturating_sub(1);

        let bar_chart = BarChart::default()
            .data(BarGroup::default().bars(&bars))
            .bar_width(bar_width)
            .bar_gap(1)
            .max(100);
        f.render_widget(bar_chart, eeg_layout[0]);

        // Stacked Labels and Values alignment
        let label_constraints: Vec<Constraint> = (0..num_bars)
            .flat_map(|_| vec![Constraint::Length(bar_width), Constraint::Length(1)])
            .collect();

        let label_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(label_constraints)
            .split(eeg_layout[1]);

        for i in 0..5 {
            let label_para = Paragraph::new(vec![
                Line::from(label_names[i]).centered(),
                Line::from(format!("{:.1}%", raw_values[i] * 100.0))
                    .centered()
                    .style(Style::default().fg(colors[i])),
            ]);
            f.render_widget(label_para, label_chunks[i * 2]);
        }
    } else {
        let empty = Paragraph::new("Waiting for EEG band data...").block(
            Block::default()
                .borders(Borders::ALL)
                .title("EEG Power Bands (%)"),
        );
        f.render_widget(empty, chunks[4]);
    }

    // MoQ Debug Section (Bottom)
    if parser.show_debug {
        // Live bottom-left frame label: negotiated protocol version + the
        // last connect's RTT (refreshed on (re)connect, not a live ping).
        let version = parser
            .moq_version
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let connect_rtt = parser.connect_rtt_ms.load(Ordering::Relaxed);
        let proto = if version.is_empty() {
            "—".to_string()
        } else {
            version
        };
        let label = format!(" {proto} · relay {connect_rtt}ms ");
        let debug_block = Block::default()
            .title(" MoQ Protocol Debug ")
            .title_bottom(Line::from(label).left_aligned())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let debug_lines: Vec<Line> = {
            let d = parser.moq_debug.lock().unwrap();
            d.iter().map(|s| Line::from(s.clone())).collect()
        };

        let debug_para = Paragraph::new(debug_lines)
            .block(debug_block)
            .style(Style::default().bg(Color::Black));

        f.render_widget(debug_para, chunks[5]);
    }

    // Drill-down settings menu — overlays everything when open (`M`).
    if parser.menu != crate::Menu::Closed {
        // The Headset levels' titles carry live state: the search, the device being paired.
        let headset_title = if parser.headset_searching {
            " Headset · searching…  [Enter connect · S search · Esc back] "
        } else {
            " Headset  [Enter connect · S search · Esc back] "
        };
        let pairing_name = parser.headset.as_ref().map_or("the device", |(n, _)| n.as_str());
        let pin_title = format!(" PIN for {pairing_name}  [Enter pair · Esc cancel] ");
        let confirm_title = format!(" Pairing {pairing_name}  [Enter yes · Esc no] ");
        // Build the current level's rows as strings (so we can size the popup).
        let (title, rows): (&str, Vec<String>) = match parser.menu {
            crate::Menu::Main => (
                " Settings  [↑↓ · →/Enter · Esc] ",
                crate::main_menu(parser)
                    .iter()
                    .map(|m| format!("  {m}  ▸"))
                    .collect(),
            ),
            crate::Menu::Headset => (
                headset_title,
                if parser.headset_rows.is_empty() {
                    vec![if parser.headset_searching {
                        "   searching for devices nearby…".to_string()
                    } else {
                        "   nothing found — switch the headset on, then S".to_string()
                    }]
                } else {
                    parser
                        .headset_rows
                        .iter()
                        .map(|row| {
                            let new = if row.paired { "" } else { "  (new)" };
                            match parser.headset.as_ref().filter(|(_, a)| *a == row.address) {
                                Some(_) => format!(" ● {}{new} — {}", row.name, headset_label(parser)),
                                None => format!("   {}{new}", row.name),
                            }
                        })
                        .collect()
                },
            ),
            crate::Menu::HeadsetPin => (
                &pin_title,
                vec![format!("   PIN: {}▏", parser.pin_input)],
            ),
            crate::Menu::HeadsetConfirm => (
                &confirm_title,
                vec![match &parser.headset_state {
                    Some(crate::HeadsetState::NeedsConfirm(code)) => format!("   Does it show {code:06}?"),
                    _ => "   Does it show the same code?".to_string(),
                }],
            ),
            crate::Menu::Relay => (
                " Relay  [Enter apply · Esc back] ",
                crate::RELAYS
                    .iter()
                    .enumerate()
                    .map(|(i, (name, url))| {
                        let a = if i == parser.sel.relay.load(Ordering::Relaxed) {
                            "●"
                        } else {
                            " "
                        };
                        let host = url
                            .trim_start_matches("https://")
                            .trim_start_matches("http://");
                        format!(" {a} {name} — {host}")
                    })
                    .collect(),
            ),
            crate::Menu::Transport => (
                " Transport  [Enter apply · Esc back] ",
                crate::TRANSPORTS
                    .iter()
                    .enumerate()
                    .map(|(i, (name, _))| {
                        let a = if i == parser.sel.transport.load(Ordering::Relaxed) {
                            "●"
                        } else {
                            " "
                        };
                        format!(" {a} {name}")
                    })
                    .collect(),
            ),
            crate::Menu::Closed => (" ", Vec::new()),
        };

        let full = f.area();
        let content_w = rows.iter().map(|r| r.chars().count()).max().unwrap_or(10) as u16;
        let w = (content_w.max(title.chars().count() as u16) + 4).min(full.width);
        let h = (rows.len() as u16 + 2).min(full.height);
        let popup = Rect {
            x: full.x + full.width.saturating_sub(w) / 2,
            y: full.y + full.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        f.render_widget(Clear, popup);

        let items: Vec<ListItem> = rows.into_iter().map(ListItem::new).collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
            .highlight_symbol("▸");

        let mut state = ListState::default();
        state.select(Some(parser.menu_cursor));
        f.render_stateful_widget(list, popup, &mut state);
    }
}

/// The Bluetooth headset's state in words, for its row in the Headset panel and the header.
fn headset_label(parser: &BrainWaveParser) -> String {
    match &parser.headset_state {
        Some(crate::HeadsetState::Pairing) => "pairing…".to_string(),
        Some(crate::HeadsetState::NeedsPin) => "pairing — enter its PIN".to_string(),
        Some(crate::HeadsetState::NeedsConfirm(code)) => format!("pairing — does it show {code:06}?"),
        Some(crate::HeadsetState::Reading) => "reading its services…".to_string(),
        Some(crate::HeadsetState::Connecting) => "connecting…".to_string(),
        Some(crate::HeadsetState::Streaming) => "streaming".to_string(),
        Some(crate::HeadsetState::NoData) => "open, no ThinkGear data".to_string(),
        Some(crate::HeadsetState::Closed) => "disconnected — M › Headset".to_string(),
        Some(crate::HeadsetState::Failed(e)) => format!("failed: {e}"),
        Some(crate::HeadsetState::Missing) | None => String::new(),
    }
}
