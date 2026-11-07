use super::*;

/// The settings bits are global: tests that switch sources hold this.
static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn random_values_differ_and_bounds_hold() {
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    fill_random(&mut a).unwrap();
    fill_random(&mut b).unwrap();
    assert_ne!(a, b);
    for _ in 0..200 {
        assert!(rand_upto(10).unwrap() <= 10);
    }
    assert_eq!(rand_upto(0).unwrap(), 0);
}

#[test]
fn long_outputs_have_no_repeated_blocks() {
    // HKDF expands at most 255*64 bytes per info: longer buffers must still be all fresh
    let mut big = vec![0u8; 3 * 8192 + 100];
    fill_random(&mut big).unwrap();
    let blocks: Vec<&[u8]> = big.chunks(8192).collect();
    assert_ne!(blocks[0], blocks[1]);
    assert_ne!(blocks[1][..100], blocks[3][..100]);
    assert!(big[3 * 8192..].iter().any(|&b| b != 0));
}

#[test]
fn key_material_never_waits_for_extra_sources() {
    let _g = SERIAL.lock().unwrap_or_else(|x| x.into_inner());
    for s in Source::ALL {
        set_enabled(s, false);
    }
    assert!(is_enabled(Source::OsCsprng), "the OS CSPRNG can't be switched off");
    mix_mouse(1.0, 2.0, 3.0);
    assert_eq!(credited_bits(), 0);
    let mut k = [0u8; 64];
    fill_random(&mut k).unwrap();
    assert!(k.iter().any(|&b| b != 0));
    apply_disabled(&[]);
    assert!(Source::ALL.into_iter().all(is_enabled));
}

#[test]
fn console_mode_collects_no_gui_sources() {
    let _g = SERIAL.lock().unwrap_or_else(|x| x.into_inner());
    set_gui(false);
    let before = SAMPLES.load(Ordering::Relaxed);
    mix_mouse(10.0, 20.0, 1.0);
    mix_mouse(30.0, 5.0, 2.0);
    mix_input_timing();
    assert_eq!(SAMPLES.load(Ordering::Relaxed), before, "no pointer samples in a console program");
    let st = status();
    for s in [Source::Mouse, Source::InputTiming, Source::WindowState] {
        assert_eq!(st.iter().find(|(x, _)| *x == s).unwrap().1, SourceStatus::Unavailable, "{s:?}");
    }
}

#[test]
fn status_reports_only_labels_and_disabled_sources() {
    let _g = SERIAL.lock().unwrap_or_else(|x| x.into_inner());
    slow_poll();
    apply_disabled(&["timers".to_string(), "no_such_source".to_string()]);
    let st = status();
    assert_eq!(st.len(), Source::ALL.len());
    assert_eq!(st.iter().find(|(s, _)| *s == Source::Timers).unwrap().1, SourceStatus::Disabled);
    assert_eq!(st.iter().find(|(s, _)| *s == Source::OsCsprng).unwrap().1, SourceStatus::Normal);
    assert!(st.iter().any(|(_, x)| *x == SourceStatus::Normal || *x == SourceStatus::Weak));
    apply_disabled(&[]);
}

#[test]
fn equal_samples_from_two_sources_give_different_pools() {
    let mut a = Pool { h: [0; 64], absorbed: 0, draws: 0, last: None, last_d: (0.0, 0.0), last_input: 0, health: vec![], fast_at: None, slow_at: None };
    let mut b = Pool { h: [0; 64], absorbed: 0, draws: 0, last: None, last_d: (0.0, 0.0), last_input: 0, health: vec![], fast_at: None, slow_at: None };
    absorb(&mut a, Source::Timers, b"same");
    absorb(&mut b, Source::Memory, b"same");
    assert_ne!(a.h, b.h, "the source code separates domains");
}
