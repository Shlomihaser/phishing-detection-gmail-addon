/**
 * Configuration object using Properties Service for secure storage.
 * 
 * To set the API_URL:
 * 1. Open Apps Script Editor
 * 2. Go to Project Settings (gear icon)
 * 3. Scroll to "Script Properties"
 * 4. Add property: API_URL = https://your-production-api.com/api/scan
 * 
 * Or run setApiUrl("https://your-api.com/api/scan") once from the editor.
 */
var CONFIG = {
  get API_URL() {
    var props = PropertiesService.getScriptProperties();
    var url = props.getProperty('API_URL');
    
    if (!url) {
      // Fallback for development - remove or change in production
      console.warn('API_URL not set in Script Properties. Using default.');
      return 'http://localhost:8000/api/scan';
    }
    
    return url;
  }
};

/**
 * Utility function to set the API URL.
 * Run this once from the Apps Script editor to configure.
 * 
 * @param {string} url - The full API endpoint URL
 */
function setApiUrl(url) {
  PropertiesService.getScriptProperties().setProperty('API_URL', url);
  console.log('API_URL set to: ' + url);
}