/**
 * Main entry point triggered when the add-on is opened.
 * @param {Object} e The event object containing message metadata.
 * @return {CardService.Card} The UI card to display in Gmail.
 */
function handleScanButtonClick(e) {

  //  Authorize access to the current email message
  var accessToken = e.messageMetadata.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  //  Retrieve the specific message object using the ID from metadata
  var messageId = e.messageMetadata.messageId
  var message = GmailApp.getMessageById(messageId);
  
  var emailData = {
    "messageId": messageId,
    "subject": message.getSubject(),
    "body": message.getPlainBody(),
    "sender": message.getFrom(),
    "date": message.getDate().toISOString(),
    "threadId": message.getThread().getId(),
    "rawContent": message.getRawContent(),
  };

  var url = CONFIG.API_URL; 

  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(emailData),
    "muteHttpExceptions": true
  };

  try {
    //  Execute the request to the Python Backend
    var response = UrlFetchApp.fetch(url, options);
    var result = JSON.parse(response.getContentText());
    console.log(JSON.stringify(result));
    // Handle cases like Validation Errors or Server Crashes
    if (response.getResponseCode() !== 200) 
      return createErrorCard("Backend Error: " + response.getResponseCode());
    
    // Email analayzed succesfully 
    return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(createResultCard(result)))
        .build();
  } catch (err) {
    // Handle network errors (e.g., ngrok tunnel is down)
    return createErrorCard("Error connecting to Backend: " + err.toString());
  }
}


