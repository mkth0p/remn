import { TRANCO_10K } from './tranco10k'

/**
 * Built-in reference lists usable with in_setting / nin_setting when the case settings define no
 * list of that name (a case setting with the same name wins). Mirror of backend/services/reference/lists.py.
 */
export const BUILTIN_LISTS: Record<string, () => string[]> = {
  tranco_10k: () => TRANCO_10K,
}
