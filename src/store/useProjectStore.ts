import { create } from 'zustand'

interface ProjectState {
  selectedNav: string
  setSelectedNav: (nav: string) => void
}

export const useProjectStore = create<ProjectState>((set) => ({
  selectedNav: 'overview', // default tab
  setSelectedNav: (nav) => set({ selectedNav: nav }),
}))
