//! ratatui drawing for discovery, files, pin, and control screens.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{format_time, help_text, help_text_cast, App, Screen};
use crate::files;

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const ERR: Color = Color::Red;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let help_h = match app.screen {
        Screen::Control if app.screen_cast => 5,
        Screen::Control => 11,
        Screen::Pin => 5,
        _ => 3,
    };
    let net_h = if app.show_net_panel() { 8 } else { 0 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(help_h),
            Constraint::Length(net_h),
            Constraint::Length(3),
        ])
        .split(area);

    match app.screen {
        Screen::Discovery => draw_discovery(frame, app, chunks[0]),
        Screen::Files => draw_files(frame, app, chunks[0]),
        Screen::AddFolder => draw_add_folder(frame, app, chunks[0]),
        Screen::Pin => draw_pin(frame, app, chunks[0]),
        Screen::Control => draw_control(frame, app, chunks[0]),
    }
    draw_keys(frame, app, chunks[1]);
    if net_h > 0 {
        draw_net(frame, app, chunks[2]);
    }
    draw_status(frame, app, chunks[3]);
}

fn split_busy(frame: &mut Frame, app: &App, area: Rect) -> Rect {
    let Some(msg) = app.busy_text() else {
        return area;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            msg,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))),
        chunks[1],
    );
    chunks[0]
}

fn draw_net(frame: &mut Frame, app: &App, area: Rect) {
    let lines_raw = app.net_log();
    let n = lines_raw.len();
    let mut lines: Vec<Line> = Vec::new();
    if lines_raw.is_empty() {
        lines.push(Line::from(Span::styled(
            "no traffic yet",
            Style::default().fg(DIM),
        )));
    } else {
        for (i, text) in lines_raw.iter().enumerate() {
            let newest = i + 1 == n;
            lines.push(Line::from(Span::styled(
                text.clone(),
                if newest {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(DIM)
                },
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(DIM))
                    .title(Span::styled(
                        " net ",
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn title_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            format!(" omacast  {title} "),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn draw_discovery(frame: &mut Frame, app: &App, area: Rect) {
    let area = split_busy(frame, app, area);
    let inner = title_block("discover");
    if app.devices.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "No AirPlay devices found.",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("Browsing _airplay._tcp.local.  IPv4 preferred."),
        ])
        .block(inner)
        .wrap(Wrap { trim: false });
        frame.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = app
        .devices
        .iter()
        .map(|d| {
            let label = format!("{:<24}  {}", d.name, d.addr_label());
            ListItem::new(Line::from(label))
        })
        .collect();

    let list = List::new(items)
        .block(inner)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    state.select(Some(app.selected_device.min(app.devices.len() - 1)));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_files(frame: &mut Frame, app: &App, area: Rect) {
    let area = split_busy(frame, app, area);
    let filter = if app.filter.is_empty() {
        "type to filter".to_string()
    } else {
        format!("/{}", app.filter)
    };
    let scan = if app.scanning { "  scanning..." } else { "" };
    let title = format!("files  {filter}  {}{scan}", app.files.len());
    let inner = title_block(&title);

    if app.filtered.is_empty() {
        let msg = if app.scanning {
            "Scanning folders...".to_string()
        } else if app.files.is_empty() {
            if app.folders.is_empty() {
                "No folders configured. Press a to add one.".to_string()
            } else {
                format!(
                    "No .mp4 / .mkv / .mov files under\n{}",
                    app.folders
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            }
        } else {
            format!("No files matching \"{}\"", app.filter)
        };
        let empty = Paragraph::new(msg).block(inner).wrap(Wrap { trim: false });
        frame.render_widget(empty, area);
        return;
    }

    let show_root = app.folders.len() > 1;
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .filter_map(|&i| app.files.get(i))
        .map(|file| ListItem::new(Line::from(files::display_name(file, show_root))))
        .collect();

    let list = List::new(items)
        .block(inner)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    state.select(Some(app.selected_file.min(app.filtered.len() - 1)));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_add_folder(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![
        Line::from(""),
        Line::from("Add a media folder (scanned recursively for .mp4 / .mkv / .mov):"),
        Line::from(""),
        Line::from(vec![
            Span::styled("  path  ", Style::default().fg(DIM)),
            Span::styled(
                format!("{}_", app.folder_input),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Folders already configured:",
            Style::default().fg(DIM),
        )),
    ];
    if app.folders.is_empty() {
        lines.push(Line::from("  (none)"));
    } else {
        for p in &app.folders {
            lines.push(Line::from(format!("  {}", p.display())));
        }
    }
    let body = Paragraph::new(lines)
        .block(title_block("add folder"))
        .wrap(Wrap { trim: false });
    frame.render_widget(body, area);
}

fn draw_pin(frame: &mut Frame, app: &App, area: Rect) {
    let area = split_busy(frame, app, area);
    let shown = if app.pin_buf.is_empty() {
        "_ _ _ _".to_string()
    } else {
        let mut chars: Vec<String> = app.pin_buf.chars().map(|c| c.to_string()).collect();
        while chars.len() < 4 {
            chars.push("_".to_string());
        }
        chars.join(" ")
    };
    let body = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "PIN shown on the TV",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("    {shown}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Enter the 4-digit code, then Enter. Esc cancels."),
    ])
    .block(title_block("pair"))
    .wrap(Wrap { trim: false });
    frame.render_widget(body, area);
}

fn draw_control(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);

    let device = app.device.as_ref().map(|d| d.name.as_str()).unwrap_or("—");
    let file = app
        .current_file
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "—".into());
    let state = if app.screen_cast {
        format!("sending to the TV — on {device}")
    } else if app.playing {
        "playing".into()
    } else {
        "paused".into()
    };
    let title = if app.screen_cast { "On TV" } else { "control" };

    let info = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("device  ", Style::default().fg(DIM)),
            Span::raw(device),
        ]),
        Line::from(vec![
            Span::styled("file    ", Style::default().fg(DIM)),
            Span::raw(file),
        ]),
        Line::from(vec![
            Span::styled("state   ", Style::default().fg(DIM)),
            Span::raw(state),
        ]),
    ])
    .block(title_block(title));
    frame.render_widget(info, chunks[0]);

    let ratio = app.progress_ratio();
    let dur_label = if app.duration > 0.0 {
        format_time(app.duration)
    } else {
        "--:--".into()
    };
    let pct = app
        .progress_percent()
        .map(|p| format!("  {p}%"))
        .unwrap_or_default();
    let approx = if app.playback_info_ok { "" } else { "  ~" };
    let label = format!(
        "{} / {}{}{}",
        format_time(app.position),
        dur_label,
        pct,
        approx
    );
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT)),
        )
        .gauge_style(Style::default().fg(ACCENT).bg(Color::Black))
        .ratio(ratio)
        .label(label);
    frame.render_widget(gauge, chunks[1]);

    if let Some(err) = &app.last_error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                err.clone(),
                Style::default().fg(ERR),
            )))
            .wrap(Wrap { trim: true }),
            chunks[2],
        );
    }
}

fn draw_keys(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " keys ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));

    let lines = match app.screen {
        Screen::Control if app.screen_cast => vec![
            Line::from(Span::styled(
                help_text_cast(Screen::Control, true),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                key_name("Esc"),
                Span::raw(" stop, back to files    "),
                key_name("q"),
                Span::raw(" stop and quit"),
            ]),
        ],
        Screen::Control => vec![
            Line::from(Span::styled(
                help_text(Screen::Control),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![key_name("Space"), Span::raw(" play / pause")]),
            Line::from(vec![
                key_name("Left / Right"),
                Span::raw(" seek 10 seconds    "),
                key_name("Shift+arrows  or  [ ]"),
                Span::raw(" seek 1 minute"),
            ]),
            Line::from(vec![
                key_name("0-9"),
                Span::raw(" jump 0% 10% ... 90%    "),
                key_name("Home / End"),
                Span::raw(" start / end"),
            ]),
            Line::from(vec![
                key_name("Esc"),
                Span::raw(" stop, back to files    "),
                key_name("q"),
                Span::raw(" stop and quit"),
            ]),
        ],
        Screen::Pin => vec![
            Line::from(Span::styled(
                help_text(Screen::Pin),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("Type the 4 digits shown on the TV, then Enter."),
        ],
        other => vec![Line::from(Span::styled(
            help_text(other),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ))],
    };

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn key_name(label: &'static str) -> Span<'static> {
    Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(Color::Black)
            .bg(ACCENT)
            .add_modifier(Modifier::BOLD),
    )
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let busy = app.busy_text();
    let shown = busy.as_deref().unwrap_or(app.status.as_str());
    let text = vec![Line::from(Span::styled(
        shown,
        Style::default().fg(if busy.is_some() {
            Color::Yellow
        } else {
            Color::White
        }),
    ))];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DIM)),
        ),
        area,
    );
}
