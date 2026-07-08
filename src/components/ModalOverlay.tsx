import { useRef } from "react";

interface Props {
  onClose?: () => void;
  children: React.ReactNode;
}

/**
 * A modal backdrop that closes on click, but only when both the press and
 * the release happened on the backdrop itself. A plain `onClick` on the
 * overlay closes it whenever a click *ends* there — including when the
 * user starts selecting text inside the modal and drags past its edge
 * before releasing the mouse button, which fires a click on the backdrop
 * even though the interaction started inside the modal.
 */
export function ModalOverlay({ onClose, children }: Props) {
  const pressStartedOnOverlay = useRef(false);

  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        pressStartedOnOverlay.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        if (onClose && e.target === e.currentTarget && pressStartedOnOverlay.current) {
          onClose();
        }
      }}
    >
      {children}
    </div>
  );
}
