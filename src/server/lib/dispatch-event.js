import logger from '../../lib/logger'

export default async (event, message, opts) => {
  try {
    await event(message, opts)
  } catch (e) {
    logger.error('EVENT_ERROR', e)
  }
}
