use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BannerCrop {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl BannerCrop {
    pub fn validate(self) -> AppResult<Self> {
        if !self.x.is_finite()
            || !self.y.is_finite()
            || !self.width.is_finite()
            || !self.height.is_finite()
        {
            return Err(AppError::Validation(
                "Banner crop values must be finite numbers".into(),
            ));
        }

        if self.x < 0.0
            || self.y < 0.0
            || self.width <= 0.0
            || self.height <= 0.0
            || self.x > 100.0
            || self.y > 100.0
            || self.width > 100.0
            || self.height > 100.0
            || self.x + self.width > 100.25
            || self.y + self.height > 100.25
        {
            return Err(AppError::Validation(
                "Banner crop must stay within the image bounds".into(),
            ));
        }

        Ok(Self {
            x: round4(self.x.clamp(0.0, 100.0)),
            y: round4(self.y.clamp(0.0, 100.0)),
            width: round4(self.width.clamp(0.01, 100.0)),
            height: round4(self.height.clamp(0.01, 100.0)),
        })
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

pub fn from_parts(
    x: Option<f64>,
    y: Option<f64>,
    width: Option<f64>,
    height: Option<f64>,
) -> Option<BannerCrop> {
    Some(BannerCrop {
        x: x?,
        y: y?,
        width: width?,
        height: height?,
    })
}

pub fn to_json(crop: Option<BannerCrop>) -> Value {
    crop.map(|c| {
        json!({
            "x": c.x,
            "y": c.y,
            "width": c.width,
            "height": c.height,
        })
    })
    .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::BannerCrop;

    #[test]
    fn validates_and_rounds_percentage_crop() {
        let crop = BannerCrop {
            x: 12.34567,
            y: 4.32104,
            width: 70.25,
            height: 24.75,
        }
        .validate()
        .expect("valid crop");

        assert_eq!(crop.x, 12.3457);
        assert_eq!(crop.y, 4.321);
        assert_eq!(crop.width, 70.25);
        assert_eq!(crop.height, 24.75);
    }

    #[test]
    fn rejects_out_of_bounds_crop() {
        assert!(
            BannerCrop {
                x: -1.0,
                y: 0.0,
                width: 50.0,
                height: 50.0,
            }
            .validate()
            .is_err()
        );
        assert!(
            BannerCrop {
                x: 75.0,
                y: 0.0,
                width: 30.0,
                height: 50.0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn rejects_non_finite_crop_values() {
        assert!(
            BannerCrop {
                x: f64::NAN,
                y: 0.0,
                width: 50.0,
                height: 50.0,
            }
            .validate()
            .is_err()
        );
    }
}
