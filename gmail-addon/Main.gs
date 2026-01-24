/**
 * Main entry point triggered when the add-on is opened.
 * @param {Object} e The event object containing message metadata.
 * @return {CardService.Card} The UI card to display in Gmail.
 */
function handleScanButtonClick(e) {
  try {
    // 1. Authorize & Get Message
    var accessToken = e.messageMetadata.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);

    var messageId = e.messageMetadata.messageId;
    var message = GmailApp.getMessageById(messageId);

    // 2. Extract Data 
    var mime = {"mime": message.getRawContent()};
    
    // 3. Send to Backend
    var options = {
      "method": "post",
      "contentType": "application/json",
      "payload": JSON.stringify(mime),
      "muteHttpExceptions": true
    };

    var response = UrlFetchApp.fetch(CONFIG.API_URL, options);
    if (response.getResponseCode() !== 200)
      throw new Error("Backend returned status " + response.getResponseCode());

    var result = JSON.parse(response.getContentText());

    // 4. Return UI Result
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(createResultCard(result)))
      .build();

  } catch (err) {
    console.error(err);
    return createErrorCard("Process failed: " + err.toString());
  }
}
