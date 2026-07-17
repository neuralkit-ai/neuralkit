use realfft::RealFftPlanner;

pub const SAMPLE_RATE: usize = 512;
pub const WINDOW_SIZE: usize = 512; // Size of the data window (in samples)
pub const SLIDING_WINDOW_STEP: usize = 128; // How often we update (128 samples = 4Hz)

#[derive(Debug, Clone, Default)]
pub struct BandData {
    pub delta: f32,
    pub theta: f32,
    pub alpha: f32,
    pub beta: f32,
    pub gamma: f32,
}

pub fn process_brain_waves(raw_values: &[i16]) -> Option<BandData> {
    if raw_values.len() < SLIDING_WINDOW_STEP {
        return None;
    }

    // 1. DC Offset Removal (Mean Subtraction)
    let mean = raw_values.iter().map(|&x| x as f32).sum::<f32>() / raw_values.len() as f32;
    let mut centered: Vec<f32> = raw_values.iter().map(|&x| x as f32 - mean).collect();

    // 2. Apply Hanning Window to reduce spectral leakage
    let len = centered.len();
    for i in 0..len {
        let window = 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / (len - 1) as f32).cos());
        centered[i] *= window;
    }

    // 3. FFT
    let mut planner = RealFftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(len);
    let mut spectrum = fft.make_output_vec();
    let _ = fft.process(&mut centered, &mut spectrum);

    // 4. Power Spectral Density (PSD)
    let psd: Vec<f32> = spectrum
        .iter()
        .map(|c| c.norm_sqr() / (SAMPLE_RATE as f32 * len as f32))
        .collect();

    // 5. Band Extraction
    let mut bands = BandData::default();

    let get_band_power = |f_start: f32, f_end: f32| -> f32 {
        let start_idx = (f_start * len as f32 / SAMPLE_RATE as f32) as usize;
        let end_idx = (f_end * len as f32 / SAMPLE_RATE as f32) as usize;
        let actual_end = end_idx.min(psd.len());
        if start_idx >= actual_end {
            return 0.0;
        }
        psd[start_idx..actual_end].iter().sum::<f32>()
    };

    // Standard EEG frequency bins
    bands.delta = get_band_power(0.5, 4.0);
    bands.theta = get_band_power(4.0, 8.0);
    bands.alpha = get_band_power(8.0, 13.0);
    bands.beta = get_band_power(13.0, 30.0);
    bands.gamma = get_band_power(30.0, 50.0);

    // Relative power normalization
    let total_power: f32 = bands.delta + bands.theta + bands.alpha + bands.beta + bands.gamma;

    if total_power > 0.0 {
        bands.delta /= total_power;
        bands.theta /= total_power;
        bands.alpha /= total_power;
        bands.beta /= total_power;
        bands.gamma /= total_power;
        Some(bands)
    } else {
        None
    }
}
