// Vitest global setup: extends `expect` with jest-dom matchers and cleans up
// the React tree after each test so tests stay isolated.
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => {
  cleanup()
})
