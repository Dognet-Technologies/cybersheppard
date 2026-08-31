// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - i18n bootstrap
// ============================================================================
// Infrastruttura di internazionalizzazione (react-i18next). L'inglese è la
// lingua base: le stringhe nuove vanno esternalizzate qui. La traduzione
// effettiva verso altre lingue è uno step successivo — aggiungere una lingua
// significa creare `locales/<lang>/translation.json` e registrarla in
// `resources` sotto.

import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import en from './locales/en/translation.json'

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
  },
  lng: 'en',
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false, // React già protegge dall'XSS
  },
})

export default i18n
