/// Sequence number tracker with RFC 9293 wraparound handling.
/// 
/// Reference point is the maximum contiguous sequence number (not the last seen).
/// Seed from SYN if present, otherwise from minimum observed sequence.
/// Window is ±2^31 from reference point.
/// Reference point updates only on confirmed continuity.

use std::cmp::Ordering;

pub const SEQ_WINDOW: u32 = 1 << 31; // ±2^31

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqTracker {
    /// The reference point: maximum confirmed contiguous sequence number.
    /// This is the "left edge" of the receive window in RFC 9293 terms.
    reference: u32,
    /// Whether the reference point has been initialized (SYN seen or first packet)
    initialized: bool,
    /// The ISN (Initial Sequence Number) from SYN, if seen
    isn: Option<u32>,
}

impl SeqTracker {
    /// Create a new SeqTracker.
    /// If `syn_seq` is Some, it's used as ISN and reference = ISN + 1 (SYN consumes 1 seq).
    /// Otherwise, reference is initialized on first packet.
    pub fn new(syn_seq: Option<u32>) -> Self {
        match syn_seq {
            Some(isn) => SeqTracker {
                reference: isn.wrapping_add(1), // SYN consumes 1 sequence number
                initialized: true,
                isn: Some(isn),
            },
            None => SeqTracker {
                reference: 0,
                initialized: false,
                isn: None,
            },
        }
    }

    /// Get the current reference point.
    pub fn reference(&self) -> u32 {
        self.reference
    }

    /// Check if tracker is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the ISN if known.
    pub fn isn(&self) -> Option<u32> {
        self.isn
    }

    /// Convert absolute sequence number to offset from stream start.
    /// Returns None if seq is outside the valid window.
    pub fn seq_to_offset(&self, abs_seq: u32) -> Option<u64> {
        if !self.initialized {
            return None;
        }
        
        // Check if seq is within window [reference - 2^31, reference + 2^31)
        let diff = abs_seq.wrapping_sub(self.reference);
        if diff >= SEQ_WINDOW {
            // seq is behind the window (too old) or ahead (future)
            return None;
        }
        
        // Valid: offset = seq - reference (as u64 to avoid overflow)
        Some(diff as u64)
    }

    /// Try to update the reference point with a new contiguous sequence number.
    /// Returns true if reference was updated.
    /// The new reference must be strictly greater than current reference
    /// and within the window (i.e., contiguous from current reference).
    pub fn try_advance(&mut self, new_contiguous_seq: u32) -> bool {
        if !self.initialized {
            // First packet initializes the tracker
            self.reference = new_contiguous_seq;
            self.initialized = true;
            if self.isn.is_none() {
                // No SYN seen, use this as base
                self.isn = Some(new_contiguous_seq);
            }
            return true;
        }

        // Check if new_contiguous_seq is strictly ahead and within window
        let diff = new_contiguous_seq.wrapping_sub(self.reference);
        if diff > 0 && diff < SEQ_WINDOW {
            self.reference = new_contiguous_seq;
            true
        } else {
            false
        }
    }

    /// Compare two sequence numbers in the context of this tracker's window.
    /// Returns Ordering based on RFC 9293 serial number arithmetic.
    pub fn cmp_seq(&self, a: u32, b: u32) -> Ordering {
        let diff = a.wrapping_sub(b);
        if diff == 0 {
            Ordering::Equal
        } else if diff < SEQ_WINDOW {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    /// Check if a sequence number is within the valid receive window.
    pub fn in_window(&self, seq: u32) -> bool {
        if !self.initialized {
            return false;
        }
        let diff = seq.wrapping_sub(self.reference);
        diff < SEQ_WINDOW
    }

    /// Get the absolute sequence number for a given offset from stream start.
    pub fn offset_to_seq(&self, offset: u64) -> Option<u32> {
        if !self.initialized {
            return None;
        }
        if offset >= SEQ_WINDOW as u64 {
            return None;
        }
        Some(self.reference.wrapping_add(offset as u32))
    }
}

impl Default for SeqTracker {
    fn default() -> Self {
        SeqTracker::new(None)
    }
}

/// Segment for reassembly: represents a contiguous piece of data with sequence info.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Absolute sequence number of first byte
    pub abs_seq: u32,
    /// Length in bytes
    pub len: usize,
    /// Frame number this segment came from
    pub frame_number: u32,
    /// Whether this segment is a retransmission (duplicate)
    pub is_retransmission: bool,
    /// Whether this segment has overlap with different data
    pub has_conflict: bool,
    /// The payload data
    pub data: Vec<u8>,
}

impl Segment {
    pub fn new(abs_seq: u32, len: usize, frame_number: u32, data: Vec<u8>) -> Self {
        Segment {
            abs_seq,
            len,
            frame_number,
            is_retransmission: false,
            has_conflict: false,
            data,
        }
    }

    /// End sequence number (exclusive)
    pub fn end_seq(&self) -> u32 {
        self.abs_seq.wrapping_add(self.len as u32)
    }

    /// Check if this segment overlaps with another
    pub fn overlaps(&self, other: &Segment) -> bool {
        // Check if ranges [abs_seq, end_seq) overlap
        let self_end = self.end_seq();
        let other_end = other.end_seq();
        
        // Using RFC 9293 comparison: a <= b iff a == b || (a - b) > 2^31
        // For overlap: not (self_end <= other.abs_seq || other_end <= self.abs_seq)
        let self_before_other = self_end == other.abs_seq || self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW;
        let other_before_self = other_end == self.abs_seq || other_end.wrapping_sub(self.abs_seq) > SEQ_WINDOW;
        
        !(self_before_other || other_before_self)
    }

    /// Check if this segment is completely before another
    pub fn is_before(&self, other: &Segment) -> bool {
        let self_end = self.end_seq();
        self_end == other.abs_seq || self_end.wrapping_sub(other.abs_seq) > SEQ_WINDOW
    }
}

/// Sort segments by (abs_seq, frame_number) for deterministic ordering.
/// Uses RFC 9293 sequence number arithmetic: a < b iff (a - b) > 2^31.
pub fn sort_segments(segments: &mut [Segment]) {
    segments.sort_by(|a, b| {
        // Compare abs_seq using RFC 9293 arithmetic
        let seq_cmp = a.abs_seq.wrapping_sub(b.abs_seq);
        if seq_cmp != 0 && seq_cmp > SEQ_WINDOW {
            // a < b in RFC 9293 sense (wrapped around)
            std::cmp::Ordering::Less
        } else if seq_cmp != 0 {
            // a > b in RFC 9293 sense
            std::cmp::Ordering::Greater
        } else {
            // Same abs_seq: sort by frame_number
            a.frame_number.cmp(&b.frame_number)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_tracker_with_syn() {
        let mut tracker = SeqTracker::new(Some(1000));
        assert_eq!(tracker.reference(), 1001); // SYN consumes 1
        assert!(tracker.is_initialized());
        assert_eq!(tracker.isn(), Some(1000));
    }

    #[test]
    fn test_seq_tracker_without_syn() {
        let tracker = SeqTracker::new(None);
        assert!(!tracker.is_initialized());
        assert_eq!(tracker.isn(), None);
    }

    #[test]
    fn test_seq_to_offset() {
        let mut tracker = SeqTracker::new(Some(1000));
        // reference = 1001
        assert_eq!(tracker.seq_to_offset(1001), Some(0));
        assert_eq!(tracker.seq_to_offset(1002), Some(1));
        assert_eq!(tracker.seq_to_offset(2000), Some(999));
        
        // Advance reference
        tracker.try_advance(2000);
        assert_eq!(tracker.reference(), 2000);
        assert_eq!(tracker.seq_to_offset(2000), Some(0));
        assert_eq!(tracker.seq_to_offset(3000), Some(1000));
    }

    #[test]
    fn test_seq_to_offset_out_of_window() {
        let tracker = SeqTracker::new(Some(1000));
        // reference = 1001
        // Window is [1001 - 2^31, 1001 + 2^31)
        // seq 0 is 1001 behind reference = diff = 0xFFFFFC01 > 2^31, so out of window
        assert_eq!(tracker.seq_to_offset(0), None);
    }

    #[test]
    fn test_wraparound() {
        let mut tracker = SeqTracker::new(Some(0xFFFFFF00));
        // reference = 0xFFFFFF01
        
        // Sequence wraps around
        let seq_wrapped = 0x00000010; // 16
        // diff = 0x10 - 0xFFFFFF01 = 0x10 + 0xFF = 0x10F < 2^31, so in window
        assert_eq!(tracker.seq_to_offset(seq_wrapped), Some(0x10F));
        
        // Advance past wraparound
        tracker.try_advance(seq_wrapped);
        assert_eq!(tracker.reference(), 0x10);
    }

    #[test]
    fn test_try_advance() {
        let mut tracker = SeqTracker::new(Some(1000));
        assert!(tracker.try_advance(2000));
        assert_eq!(tracker.reference(), 2000);
        
        // Cannot go backwards
        assert!(!tracker.try_advance(1500));
        assert_eq!(tracker.reference(), 2000);
        
        // Cannot jump too far (outside window)
        assert!(!tracker.try_advance(0x8000_0000 + 2000)); // > 2^31 ahead
    }

    #[test]
    fn test_segment_overlap() {
        let seg1 = Segment::new(1000, 100, 1, vec![0; 100]);
        let seg2 = Segment::new(1050, 100, 2, vec![0; 100]);
        assert!(seg1.overlaps(&seg2));
        assert!(seg2.overlaps(&seg1));
    }

    #[test]
    fn test_segment_no_overlap() {
        let seg1 = Segment::new(1000, 100, 1, vec![0; 100]);
        let seg2 = Segment::new(1100, 100, 2, vec![0; 100]);
        assert!(!seg1.overlaps(&seg2));
    }

    #[test]
    fn test_segment_wraparound_overlap() {
        // Segment near wrap boundary
        let seg1 = Segment::new(0xFFFFFF00, 0x200, 1, vec![0; 0x200]);
        // Segment after wrap
        let seg2 = Segment::new(0x00000050, 100, 2, vec![0; 100]);
        assert!(seg1.overlaps(&seg2));
    }

    #[test]
    fn test_sort_segments() {
        let mut segs = vec![
            Segment::new(2000, 100, 2, vec![]),
            Segment::new(1000, 100, 1, vec![]),
            Segment::new(1000, 100, 3, vec![]), // Same seq, later frame
        ];
        sort_segments(&mut segs);
        assert_eq!(segs[0].abs_seq, 1000);
        assert_eq!(segs[0].frame_number, 1);
        assert_eq!(segs[1].abs_seq, 1000);
        assert_eq!(segs[1].frame_number, 3);
        assert_eq!(segs[2].abs_seq, 2000);
    }

    #[test]
    fn test_sort_segments_wraparound() {
        let mut segs = vec![
            Segment::new(0xFFFFFF00, 100, 1, vec![]),
            Segment::new(0x00000010, 100, 2, vec![]),
        ];
        sort_segments(&mut segs);
        // 0xFFFFFF00 comes before 0x00000010 in RFC 9293 (it's "less" by 0xF0)
        assert_eq!(segs[0].abs_seq, 0xFFFFFF00);
        assert_eq!(segs[1].abs_seq, 0x00000010);
    }
}