/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface ChartInstance {
  destroy(): void;
  update(mode?: string): void;
  data: {
    labels: string[];
    datasets: { data: number[]; [key: string]: unknown }[];
  };
}

declare const Chart: {
  new (ctx: CanvasRenderingContext2D, config: unknown): ChartInstance;
  defaults: { color: string; borderColor: string; font: { family: string } };
};

declare namespace bootstrap {
  class Modal {
    constructor(el: Element | null);
    show(): void;
    hide(): void;
    static getInstance(el: Element | null): Modal | null;
    static getOrCreateInstance(el: Element | null): Modal;
  }
}
