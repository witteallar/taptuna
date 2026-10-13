/// Stream reassembly: converts TCP segments into directional byte streams
/// with gap/ambiguity tracking and configurable overlap policies.

use crate::seq::{Segment, SeqTracker, sort_segments, SEQ_WINDOW};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapPolicy {
    FirstWins,
    LastWins,
    HaltAndMark,
}

impl Default for OverlapPolicy {
    fn default() -> Self {
        OverlapPolicy::FirstWins
    }
}

impl OverlapPolicy {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "first_wins" => Some(OverlapPolicy::FirstWins),
            "last_wins" => Some(OverlapPolicy::LastWins),
            "halt_and_mark" => Some(OverlapPolicy::HaltAndMark),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Gap {
    /// Offset in reassembled stream (bytes from stream_start)
    pub offset: u64,
    /// Length of gap in bytes
    pub length: u64,
    /// Frame numbers where gap was detected
    pub frames: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Ambiguity {
    /// Offset in reassembled stream
    pub offset: u64,
    /// Length of ambiguous region
    pub length: u64,
    /// Frame numbers involved
    pub frames: Vec<u32>,
    /// Policy applied
    pub policy: OverlapPolicy,
}

#[derive(Debug, Clone)]
pub struct ReassembledStream {
    /// Reassembled bytes (contiguous data only, gaps not included - zeros for gaps)
    pub data: Vec<u8>,
    /// Gaps in the stream
    pub gaps: Vec<Gap>,
    /// Ambiguities (overlaps with different data)
    pub ambiguities: Vec<Ambiguity>,
    /// Total bytes reassembled (including gaps)
    pub total_bytes: u64,
    /// Stream start absolute sequence number
    pub stream_start_abs_seq: u32,
    /// Whether roles established (SYN seen)
    pub roles_established: bool,
    /// Per-segment info for byte_map
    pub segments: Vec<StreamSegmentInfo>,
}

#[derive(Debug, Clone)]
pub struct StreamSegmentInfo {
    pub stream_offset: u64,
    pub length: usize,
    pub abs_seq_start: u32,
    pub abs_seq_end: u32, // inclusive
    pub status: SegmentStatus,
    pub first_frame: u32,
    pub last_frame: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentStatus {
    Clean,
    Overlap,
    GapBefore,
}

#[derive(Debug, Clone)]
pub struct ReassemblyInput {
    pub segments: Vec<Segment>,
    pub syn_seq: Option<u32>,
    pub overlap_policy: OverlapPolicy,
}

impl ReassemblyInput {
    pub fn new(segments: Vec<Segment>, syn_seq: Option<u32>, overlap_policy: OverlapPolicy) -> Self {
        ReassemblyInput {
            segments,
            syn_seq,
            overlap_policy,
        }
    }
}

pub fn reassemble(input: ReassemblyInput) -> ReassembledStream {
    let mut segments = input.segments;
    
    // Sort by (abs_seq, frame_number) for determinism
    sort_segments(&mut segments);
    
    // Initialize SeqTracker
    let mut tracker = SeqTracker::new(input.syn_seq);
    let roles_established = input.syn_seq.is_some();
    
    // Filter out zero-length segments (tcp.len == 0)
    segments.retain(|s| s.len > 0);
    
    // Deduplicate identical retransmissions
    // Identical = same abs_seq, same len, same data
    let mut deduped: Vec<Segment> = Vec::new();
    for seg in segments {
        if let Some(last) = deduped.last_mut() {
            if last.abs_seq == seg.abs_seq && last.len == seg.len && last.data == seg.data {
                // Mark as retransmission, don't add to deduped
                // But we keep the original packet info
                continue;
            }
        }
        deduped.push(seg);
    }
    let segments = deduped;
    
    // If no SYN and we have segments, initialize tracker with first segment's seq
    let mut stream_start_abs_seq = if roles_established {
        tracker.reference()
    } else if let Some(first_seg) = segments.first() {
        // Initialize tracker with first segment's seq (will be treated as stream start)
        tracker = SeqTracker::new(Some(first_seg.abs_seq.wrapping_sub(1)));
        first_seg.abs_seq
    } else {
        0
    };
    
    // Process segments
    let mut output_data = Vec::new();
    let mut gaps = Vec::new();
    let mut ambiguities = Vec::new();
    let mut stream_segments = Vec::new();
    
    // Track the end of contiguous data written so far
    let mut contiguous_end_offset: u64 = 0;
    
    for seg in &segments {
        let seg_offset = match tracker.seq_to_offset(seg.abs_seq) {
            Some(o) => o,
            None => {
                // Segment outside window - skip
                continue;
            }
        };
        
        let seg_end_seq = seg.end_seq();
        let seg_end_offset = match tracker.seq_to_offset(seg_end_seq) {
            Some(o) => o,
            None => {
                // End outside window
                continue;
            }
        };
        
        // Pre-calculate for segment info
        let abs_seq_end = seg_end_seq.wrapping_sub(1);
        
        // Check for gap before this segment (gap between contiguous_end_offset and seg_offset)
        if seg_offset > contiguous_end_offset {
            let gap_len = seg_offset - contiguous_end_offset;
            gaps.push(Gap {
                offset: contiguous_end_offset,
                length: gap_len,
                frames: vec![seg.frame_number],
            });
            
            stream_segments.push(StreamSegmentInfo {
                stream_offset: contiguous_end_offset,
                length: 0,
                abs_seq_start: tracker.offset_to_seq(contiguous_end_offset).unwrap_or(0),
                abs_seq_end: tracker.offset_to_seq(contiguous_end_offset).unwrap_or(0).wrapping_sub(1),
                status: SegmentStatus::GapBefore,
                first_frame: seg.frame_number,
                last_frame: seg.frame_number,
            });
            
            // Extend output_data with zeros for the gap
            let needed_len = seg_offset as usize;
            if output_data.len() < needed_len {
                output_data.resize(needed_len, 0);
            }
            
            contiguous_end_offset = seg_offset;
        }
        
        // Check for overlap with already written data in output_data
        let data_end_offset = seg_offset + seg.len as u64;
        let overlap_len = if data_end_offset >= output_data.len() as u64 && seg_offset < output_data.len() as u64 {
            // Overlap with existing data in output_data
            output_data.len() as u64 - seg_offset
        } else {
            0
        };
        
        if overlap_len > 0 && overlap_len <= seg.len as u64 {
            // There's an overlap with existing data
            let existing_data = &output_data[seg_offset as usize..seg_offset as usize + overlap_len as usize];
            let new_data = &seg.data[0..overlap_len as usize];
            
            let has_conflict = existing_data != new_data;
            
            if has_conflict {
                ambiguities.push(Ambiguity {
                    offset: seg_offset,
                    length: overlap_len,
                    frames: vec![seg.frame_number],
                    policy: input.overlap_policy,
                });
                
                match input.overlap_policy {
                    OverlapPolicy::FirstWins => {
                        // Keep existing data, don't overwrite
                    }
                    OverlapPolicy::LastWins => {
                        // Replace overlapping part with new segment's overlap portion
                        let start = seg_offset as usize;
                        let end = (seg_offset + overlap_len) as usize;
                        if start < output_data.len() && end <= output_data.len() {
                            let overlap_data = &seg.data[0..overlap_len as usize];
                            output_data.splice(start..end, overlap_data.iter().cloned());
                        }
                    }
                    OverlapPolicy::HaltAndMark => {
                        // Mark ambiguity but don't write conflicting data
                        // Leave zeros for the ambiguous region (already there from gap handling)
                    }
                }
            }
            
            // Write non-overlapping tail
            let tail_start = overlap_len as usize;
            if tail_start < seg.data.len() {
                let tail = &seg.data[tail_start..];
                let needed_len = (seg_offset + seg.len as u64) as usize;
                if output_data.len() < needed_len {
                    output_data.resize(needed_len, 0);
                }
                // Write tail at the correct position: seg_offset + tail_start to seg_offset + seg.data.len()
                let dest_start = seg_offset as usize + tail_start;
                let dest_end = seg_offset as usize + seg.data.len();
                output_data[dest_start..dest_end].copy_from_slice(tail);
            }
        } else {
            // No overlap with existing data (or segment is entirely before current data)
            let needed_len = (seg_offset + seg.len as u64) as usize;
            if output_data.len() < needed_len {
                output_data.resize(needed_len, 0);
            }
            output_data[seg_offset as usize..needed_len].copy_from_slice(&seg.data);
        }
        
        // Update contiguous_end_offset if this segment extends the contiguous data
        // This happens when the segment starts at or before the current contiguous end
        // and extends beyond it
        if seg_offset <= contiguous_end_offset && data_end_offset > contiguous_end_offset {
            contiguous_end_offset = data_end_offset;
        } else if seg_offset == contiguous_end_offset {
            contiguous_end_offset = data_end_offset;
        }
        
        // Record segment info
        let status = if overlap_len > 0 {
            SegmentStatus::Overlap
        } else if seg_offset > contiguous_end_offset {
            SegmentStatus::GapBefore
        } else {
            SegmentStatus::Clean
        };
        
        let abs_seq_start = seg.abs_seq;
        
        stream_segments.push(StreamSegmentInfo {
            stream_offset: seg_offset,
            length: seg.len,
            abs_seq_start,
            abs_seq_end,
            status,
            first_frame: seg.frame_number,
            last_frame: seg.frame_number,
        });
    }
    
    ReassembledStream {
        data: output_data,
        gaps,
        ambiguities,
        total_bytes: contiguous_end_offset,
        stream_start_abs_seq,
        roles_established,
        segments: stream_segments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::Segment;

    fn make_seg(seq: u32, len: usize, frame: u32, data: &[u8]) -> Segment {
        Segment::new(seq, len, frame, data.to_vec())
    }

    #[test]
    fn test_reassemble_simple() {
        let segs = vec![
            make_seg(1000, 5, 1, b"Hello"),
            make_seg(1005, 5, 2, b"World"),
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        assert_eq!(result.data, b"HelloWorld");
        assert!(result.gaps.is_empty());
        assert!(result.ambiguities.is_empty());
        assert_eq!(result.stream_start_abs_seq, 1000); // ISN+1
        assert!(result.roles_established);
    }

    #[test]
    fn test_reassemble_with_gap() {
        let segs = vec![
            make_seg(1000, 5, 1, b"Hello"),
            make_seg(1015, 5, 2, b"World"), // Gap of 10 bytes
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        // Data includes zeros for gaps: 5 + 10 gap + 5 = 20
        assert_eq!(result.data.len(), 20);
        assert_eq!(result.gaps.len(), 1);
        assert_eq!(result.gaps[0].offset, 5);
        assert_eq!(result.gaps[0].length, 10);
        assert_eq!(&result.data[0..5], b"Hello");
        assert_eq!(&result.data[5..15], &[0u8; 10]);
        assert_eq!(&result.data[15..20], b"World");
    }

    #[test]
    fn test_reassemble_overlap_first_wins() {
        // seg1: 1000-1010 (10 bytes): "HelloWorld"
        // seg2: 1005-1015 (10 bytes): "XXXXXDiffe" (first 10 of "XXXXXDifferent")
        // Overlap: 1005-1010 (5 bytes)
        // First wins: keep seg1's "World" (1005-1010), then seg2's tail "Diffe" (1010-1015)
        let segs = vec![
            make_seg(1000, 10, 1, b"HelloWorld"),
            make_seg(1005, 10, 2, b"XXXXXDiffe"),
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        // Data: "Hello" + "World" + "Diffe" = 15 bytes
        assert_eq!(result.data.len(), 15);
        assert_eq!(&result.data[0..5], b"Hello");
        assert_eq!(&result.data[5..10], b"World");
        assert_eq!(&result.data[10..15], b"Diffe");
        assert_eq!(result.ambiguities.len(), 1);
    }

    #[test]
    fn test_reassemble_overlap_last_wins() {
        // seg1: 1000-1010 (10 bytes): "HelloWorld"
        // seg2: 1005-1015 (10 bytes): "XXXXXDiffe"
        // Overlap: 1005-1010 (5 bytes)
        // Last wins: replace overlap with seg2's "XXXXX", then seg2's tail "Diffe"
        let segs = vec![
            make_seg(1000, 10, 1, b"HelloWorld"),
            make_seg(1005, 10, 2, b"XXXXXDiffe"),
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::LastWins);
        let result = reassemble(input);
        
        // Data: "Hello" + "XXXXX" + "Diffe" = 15 bytes
        assert_eq!(result.data.len(), 15);
        assert_eq!(&result.data[0..5], b"Hello");
        assert_eq!(&result.data[5..10], b"XXXXX");
        assert_eq!(&result.data[10..15], b"Diffe");
    }

    #[test]
    fn test_reassemble_identical_retransmission() {
        let segs = vec![
            make_seg(1000, 10, 1, b"HelloWorld"),
            make_seg(1000, 10, 2, b"HelloWorld"), // Identical retransmission
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        assert_eq!(result.data, b"HelloWorld");
        assert_eq!(result.segments.len(), 1); // Only one segment kept
    }

    #[test]
    fn test_reassemble_different_overlap() {
        // seg1: 1000-1010: "HelloWorld"
        // seg2: 1000-1010: "Different!" (10 bytes)
        // Same seq, different data - ambiguity detected
        let segs = vec![
            make_seg(1000, 10, 1, b"HelloWorld"),
            make_seg(1000, 10, 2, b"Different!"),
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        // Should detect ambiguity
        assert_eq!(result.ambiguities.len(), 1);
        // First wins keeps first
        assert_eq!(result.data, b"HelloWorld");
    }

    #[test]
    fn test_reassemble_wraparound() {
        // SYN = 0xFFFFFF00 - 1 = 0xFFFFFEFF
        // stream_start = 0xFFFFFF00
        // seg1: 0xFFFFFF00, len 100 -> offset 0-100
        // seg2: 0x00000010, len 50 -> offset 272-322 (wrapped)
        // Gap: 100-272 (172 bytes)
        // Total: 322 bytes
        let segs = vec![
            make_seg(0xFFFFFF00, 100, 1, &vec![0xAA; 100]),
            make_seg(0x00000010, 50, 2, &vec![0xBB; 50]),
        ];
        let input = ReassemblyInput::new(segs, Some(0xFFFFFF00 - 1), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        assert_eq!(result.data.len(), 322);
        assert!(result.roles_established);
        // Check gap
        assert_eq!(result.gaps.len(), 1);
        assert_eq!(result.gaps[0].offset, 100);
        assert_eq!(result.gaps[0].length, 172);
    }

    #[test]
    fn test_reassemble_no_syn() {
        let segs = vec![
            make_seg(1000, 5, 1, b"Hello"),
            make_seg(1005, 5, 2, b"World"),
        ];
        let input = ReassemblyInput::new(segs, None, OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        assert!(!result.roles_established);
        // First packet initializes tracker
        assert_eq!(result.stream_start_abs_seq, 1000);
        // Data: "Hello" + "World" = 10 bytes (contiguous)
        assert_eq!(result.data, b"HelloWorld");
    }

    #[test]
    fn test_zero_len_segments_ignored() {
        let segs = vec![
            make_seg(1000, 5, 1, b"Hello"),
            make_seg(1010, 0, 2, b""), // Zero length - filtered
            make_seg(1020, 5, 3, b"World"),
        ];
        let input = ReassemblyInput::new(segs, Some(999), OverlapPolicy::FirstWins);
        let result = reassemble(input);
        
        // seg1 at 1000-1005 (offset 0-5), seg3 at 1020-1025 (offset 20-25)
        // Gap: 1005-1020 = 15 bytes
        // Data: "Hello" + 15 zeros + "World" = 25 bytes
        assert_eq!(result.data.len(), 25);
        assert_eq!(&result.data[0..5], b"Hello");
        assert_eq!(&result.data[5..20], &[0u8; 15]);
        assert_eq!(&result.data[20..25], b"World");
    }
}