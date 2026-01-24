function createResultCard(result) {
  var confidence = (result.confidence || 0).toFixed(1);
  var mlScore = (result.details.ml_score || 0).toFixed(1);
  var color, label;

  // Backend returns uppercase status (SAFE, SUSPICIOUS, DANGEROUS)
  switch ((result.status || '').toLowerCase()) {
    case 'safe':
      color = '#34A853'; 
      label = 'Verified Safe';
      break;
    case 'suspicious':
      color = '#FBBC04'; 
      label = 'Potential Risk';
      break;
    case 'dangerous':
      color = '#EA4335'; 
      label = 'Dangerous Site';
      break;
    default:
      color = '#70757a'; 
      icon = CardService.Icon.NONE;
      label = 'Unknown Status';
  }

  var section = CardService.newCardSection();

  
section.addWidget(
    CardService.newDecoratedText()
      .setText('<b><font color="' + color + '">' + label + '</font></b>'));

  var signals = result.key_signals || result.reasons || [];
  var signalsText = "<b>Key Signals:</b><br>• " + (signals.length > 0 ? signals.join("<br>• ") : "No common phishing indicators.");
  section.addWidget(CardService.newTextParagraph().setText(signalsText));

  section.addWidget(CardService.newTextParagraph()
      .setText("<font color=\"#70757a\"><i>Confidence: " + confidence + "% | AI Model: " + mlScore + "%</i></font>"));

  return CardService.newCardBuilder()
      .addSection(section)
      .build();
}

function onGmailMessageOpen(e) {
  var section = CardService.newCardSection();

  section.addWidget(CardService.newTextParagraph()
      .setText("Scan this message to verify the sender's identity and detect potential phishing threats."));

  var action = CardService.newAction().setFunctionName('handleScanButtonClick');
  var button = CardService.newTextButton()
      .setText("SCAN THIS EMAIL")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(action);

  section.addWidget(CardService.newButtonSet().addButton(button));

  return CardService.newCardBuilder()
      .addSection(section) 
      .build();
}
/**
 * Error UI  
 */
function createErrorCard(errorMsg) {
  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Error"))
      .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(errorMsg)))
      .build();
}