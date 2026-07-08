import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ModalOverlay } from "./ModalOverlay";

describe("ModalOverlay", () => {
  it("closes when both the press and the release happen on the backdrop", () => {
    const onClose = vi.fn();
    render(
      <ModalOverlay onClose={onClose}>
        <button>inside</button>
      </ModalOverlay>,
    );
    const overlay = screen.getByRole("button").parentElement as HTMLElement;

    fireEvent.mouseDown(overlay);
    fireEvent.click(overlay);

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not close when a text-selection drag starts inside and ends over the backdrop", () => {
    // Regression test: selecting text inside the modal and dragging past
    // its edge releases the mouse over the backdrop, which used to be
    // indistinguishable from an actual backdrop click.
    const onClose = vi.fn();
    render(
      <ModalOverlay onClose={onClose}>
        <button>inside</button>
      </ModalOverlay>,
    );
    const inner = screen.getByRole("button");
    const overlay = inner.parentElement as HTMLElement;

    fireEvent.mouseDown(inner);
    fireEvent.click(overlay);

    expect(onClose).not.toHaveBeenCalled();
  });

  it("does not close when clicking inside the modal content normally", () => {
    const onClose = vi.fn();
    render(
      <ModalOverlay onClose={onClose}>
        <button>inside</button>
      </ModalOverlay>,
    );
    const inner = screen.getByRole("button");

    fireEvent.mouseDown(inner);
    fireEvent.click(inner);

    expect(onClose).not.toHaveBeenCalled();
  });

  it("does nothing when no onClose is provided", () => {
    render(
      <ModalOverlay>
        <button>inside</button>
      </ModalOverlay>,
    );
    const overlay = screen.getByRole("button").parentElement as HTMLElement;

    expect(() => {
      fireEvent.mouseDown(overlay);
      fireEvent.click(overlay);
    }).not.toThrow();
  });
});
