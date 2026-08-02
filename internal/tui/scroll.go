package tui

// scrollState is the whole scrollback implementation (docs/tui.md D3 keeps
// bubbles out): an offset, a clamp, and a follow-bottom latch. It is a value
// type so Update stays pure — every method returns a new state.
//
// follow means "stay pinned to the bottom as content grows". Any upward
// movement drops it; `G` re-engages it. The dashboard's mirror table does not
// use follow (rows are sorted, not appended), but the refusals pane will
// (T2), and one region type serving both is the point.
type scrollState struct {
	offset int
	follow bool
}

// maxOffset is the largest offset that still fills the region. Nothing to
// scroll means offset 0, never a negative window.
func maxOffset(total, visible int) int {
	if visible < 1 || total <= visible {
		return 0
	}
	return total - visible
}

// clamp re-seats the offset after the content or the region resized. A
// following region is re-pinned to the bottom rather than left where it was.
func (s scrollState) clamp(total, visible int) scrollState {
	max := maxOffset(total, visible)
	if s.follow {
		s.offset = max
		return s
	}
	if s.offset > max {
		s.offset = max
	}
	if s.offset < 0 {
		s.offset = 0
	}
	return s
}

// up and down move from where the region is actually drawn, which is why both
// clamp first: a following region's stored offset is 0 while it renders at the
// bottom, and moving from the stored value would jump the view to the top on
// the first keypress.
func (s scrollState) up(n, total, visible int) scrollState {
	s = s.clamp(total, visible)
	s.follow = false
	s.offset -= n
	if s.offset < 0 {
		s.offset = 0
	}
	return s
}

func (s scrollState) down(n, total, visible int) scrollState {
	s = s.clamp(total, visible)
	s.offset += n
	max := maxOffset(total, visible)
	if s.offset >= max {
		s.offset = max
	}
	return s
}

func (s scrollState) top() scrollState {
	s.follow = false
	s.offset = 0
	return s
}

func (s scrollState) bottom(total, visible int) scrollState {
	s.follow = true
	s.offset = maxOffset(total, visible)
	return s
}

// reveal scrolls the region the least it can to bring [first,last] into view:
// the whole block when it fits, its first line when it does not. It is the
// doctor view's cursor motion — a cursor list scrolls because the cursor left
// the window, never because the offset moved on its own.
func (s scrollState) reveal(first, last, total, visible int) scrollState {
	s = s.clamp(total, visible)
	s.follow = false
	if last >= s.offset+visible {
		s.offset = last - visible + 1
	}
	if s.offset > first {
		s.offset = first
	}
	if s.offset < 0 {
		s.offset = 0
	}
	return s.clamp(total, visible)
}

// window is the [lo,hi) slice of a `total`-line region visible in `visible`
// rows, with the offset clamped first so a stale offset can never panic a
// slice expression.
func (s scrollState) window(total, visible int) (lo, hi int) {
	if visible < 1 || total < 1 {
		return 0, 0
	}
	s = s.clamp(total, visible)
	lo = s.offset
	hi = lo + visible
	if hi > total {
		hi = total
	}
	return lo, hi
}

// region names which single area the scroll keys drive (§4.1). There is
// exactly one at a time, and every renderer asks before applying m.scroll:
// a region that is not the current one renders its own default rather than
// somebody else's offset.
type region int

const (
	regionMirror region = iota
	regionRefusals
	regionHelp
	// regionDoctor is the doctor findings list, where j/k move a cursor and
	// the offset follows it (§4.1's doctor row redefines the scroll keys).
	regionDoctor
	// regionNone is the switcher overlay, where j/k move a cursor.
	regionNone
)

// scrollRegion names the one region the keys drive right now. The doctor view
// outranks an open refusals pane: §4.1 redefines j/k as cursor motion there,
// and the pane keeps following its newest line underneath — a cursor the keys
// cannot reach would be worse than a pane that scrolls itself.
func (m Model) scrollRegion() region {
	switch {
	case m.overlay == overlayHelp:
		return regionHelp
	case m.overlay == overlaySwitcher:
		return regionNone
	case m.view == viewDoctor:
		return regionDoctor
	case m.pane == paneRefusals:
		return regionRefusals
	}
	return regionMirror
}

// freshScroll is the state a region starts at. The refusals pane opens
// following the newest line (§3.2); a table or a findings list opens at its
// top, so follow latches only when the pane really is the current region.
func (m Model) freshScroll() scrollState {
	return scrollState{follow: m.scrollRegion() == regionRefusals}
}

// scrollVisible and scrollTotal size whichever region scrollRegion names, so
// the key arms in Update need to know nothing about which view is open.
func (m Model) scrollVisible() int {
	if m.width <= 0 || m.height <= 0 {
		return 0
	}
	lo := m.layout()
	switch m.scrollRegion() {
	case regionHelp:
		return m.helpVisible(lo)
	case regionRefusals:
		return max(0, m.paneLines(lo)-1)
	case regionDoctor:
		return m.doctorBudget(lo)
	case regionNone:
		return 0
	}
	s := m.selectedSnap()
	if s == nil {
		return 0
	}
	return m.rowBudget(lo, s)
}

func (m Model) scrollTotal() int {
	switch m.scrollRegion() {
	case regionHelp:
		return len(helpBody(m.keys))
	case regionRefusals:
		return len(m.refusals[m.selected])
	case regionDoctor:
		rows, _ := m.doctorRows(m.layout())
		return len(rows)
	case regionNone:
		return 0
	}
	s := m.selectedSnap()
	if s == nil {
		return 0
	}
	return len(s.State.Mirror.Entries)
}
