function createResultCard(result) {
  var confidence = (result.confidence || 0).toFixed(1);
  var rawStatus = (result.status || 'unknown').toLowerCase();
  
  // 1. Theme Configuration
  var theme = {
    safe: { 
      color: "#188038", // Green
      iconUrl: "https://www.gstatic.com/images/icons/material/system/2x/check_circle_black_48dp.png",
      label: "VERIFIED SAFE",
      subtext: "No threats detected."
    },
    suspicious: { 
      color: "#F29900", // Yellow/Orange
      iconUrl: "https://www.gstatic.com/images/icons/material/system/2x/warning_black_48dp.png", 
      label: "POTENTIAL RISK",
      subtext: "Exercise caution with this email."
    },
    dangerous: { 
      color: "#D93025", // Red
      iconUrl: "https://www.gstatic.com/images/icons/material/system/2x/error_black_48dp.png", 
      label: "DANGEROUS",
      subtext: "Do not click links or open attachments."
    },
    unknown: { 
      color: "#5F6368", // Grey
      iconUrl: "https://www.gstatic.com/images/icons/material/system/2x/help_black_48dp.png", 
      label: "UNKNOWN STATUS",
      subtext: "Analysis could not complete."
    }
  };

  var style = theme[rawStatus] || theme.unknown;

  // 2. Header Section (Status & Score)
  var statusSection = CardService.newCardSection();

  // Status Banner
  statusSection.addWidget(
    CardService.newDecoratedText()
      .setText("<b><font size='5' color='" + style.color + "'>" + style.label + "</font></b>")
      .setBottomLabel(style.subtext)
      .setStartIcon(CardService.newIconImage().setIconUrl(style.iconUrl))
      .setWrapText(true)
  );

  // Risk Score Visualization (Large Text)
  // We use a clean fraction look.
  statusSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Risk Score")
      .setText("<b><font size='6' color='" + style.color + "'>" + confidence + "</font></b> <font size='4' color='#757575'>/ 100</font>")
      .setWrapText(false) // Keep on one line
  );


  // 3. Details Section (Signals)
  var detailsSection = CardService.newCardSection()
      .setHeader("Analysis Details");
      //.setCollapsible(true); // Optional: make it collapsible if long

  var signals = result.key_signals || result.reasons || [];
  
  if (signals.length > 0) {
    signals.forEach(function(signal) {
      // Clean up the signal text if needed
      var cleanSignal = signal.replace(/^(CRITICAL:|WARNING:)\s*/, ""); 
      
      var icon = "https://www.gstatic.com/images/icons/material/system/1x/info_black_24dp.png";
      if (signal.toUpperCase().includes("CRITICAL")) {
         icon = "https://www.gstatic.com/images/icons/material/system/1x/report_problem_black_24dp.png";
      }

      detailsSection.addWidget(
        CardService.newDecoratedText()
          .setText(cleanSignal)
          .setStartIcon(CardService.newIconImage().setIconUrl(icon))
          .setWrapText(true)
      );
    });
  } else {
     detailsSection.addWidget(
        CardService.newDecoratedText()
          .setText("No specific phishing indicators found.")
          .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/thumb_up_black_24dp.png"))
     );
  }


  // Build Card
  return CardService.newCardBuilder()
      .setName("ResultCard")
      .setHeader(CardService.newCardHeader().setTitle("Scan Results"))
      .addSection(statusSection)
      .addSection(detailsSection)
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
  var section = CardService.newCardSection();

  // 1. Error Header
  section.addWidget(
    CardService.newDecoratedText()
      .setText("<b><font size='5' color='#B00020'>Analysis Failed</font></b>")
      .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/2x/error_outline_black_48dp.png"))
      .setWrapText(true)
  );

  // 2. Error Message
  section.addWidget(
    CardService.newTextParagraph()
      .setText("<b>Details:</b><br>" + errorMsg)
  );

  // 3. Retry Hint
  section.addWidget(
    CardService.newTextParagraph()
      .setText("<font color='#757575'>Please check your connection and try again.</font>")
  );

  return CardService.newCardBuilder()
      .setName("ErrorCard")
      .setHeader(CardService.newCardHeader().setTitle("System Error"))
      .addSection(section)
      .build();
}