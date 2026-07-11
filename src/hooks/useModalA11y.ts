/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared accessibility/UX behavior for the app's bespoke modal overlays, which each render as a
 * `fixed inset-0` backdrop (onClick={onClose}) wrapping a stop-propagation dialog box. On its own
 * that pattern closes on backdrop-click but ignores the keyboard. This hook adds the parts a real
 * dialog needs:
 *
 *  - **Escape closes** the modal (listener is active only while open).
 *  - **Focus moves into the dialog** on open (first form field, else first button, else the box),
 *    and is **restored** to the previously-focused element on close — so keyboard users don't get
 *    dumped back at the top of the page.
 *
 * Pair it with `role="dialog" aria-modal="true"` + an aria-label on the dialog box, and attach the
 * returned ref to that box. `onClose` is read through a ref so an inline `() => setOpen(false)`
 * parent callback doesn't re-run the effect (which would steal focus back on every render).
 */
import { useEffect, useRef } from 'react';

export function useModalA11y(open: boolean, onClose: () => void) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onCloseRef.current?.();
      }
    };
    document.addEventListener('keydown', onKey);

    // Prefer a form field so typing starts immediately; otherwise the first button; otherwise the box.
    const box = dialogRef.current;
    if (box) {
      const field = box.querySelector<HTMLElement>('input:not([disabled]), textarea, select');
      const focusable = field || box.querySelector<HTMLElement>('button, [href], [tabindex]:not([tabindex="-1"])');
      (focusable || box).focus();
    }

    return () => {
      document.removeEventListener('keydown', onKey);
      previouslyFocused?.focus?.();
    };
  }, [open]);

  return dialogRef;
}
