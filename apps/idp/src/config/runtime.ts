/**
 * Runtime role selection.
 *
 * Darboon runs the same image in one of three roles, selected by DARBOON_ROLE:
 *  - 'api'    : serves HTTP (auth/token/admin) and enqueues jobs; does NOT
 *               consume queues.
 *  - 'worker' : consumes queues (OTP SMS, email, key rotation); no public API.
 *  - 'all'    : both (default) — convenient for local development and small deploys.
 *
 * Read from process.env (not ConfigService) because the role is needed at
 * module-definition time, before the Nest DI container is built.
 */
export type DarboonRole = 'api' | 'worker' | 'all';

export const getRole = (): DarboonRole => {
  const role = process.env.DARBOON_ROLE;
  return role === 'api' || role === 'worker' ? role : 'all';
};

/** True when this process should serve the public API. */
export const runsApi = (): boolean => getRole() !== 'worker';

/** True when this process should consume queues (OTP/email/key-rotation). */
export const runsWorker = (): boolean => getRole() !== 'api';
