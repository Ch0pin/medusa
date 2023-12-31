//----------------------begin of beautifiers.js-------------------------------------

var colorLog = function (input, kwargs){
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
}

function log(str) {
    console.log(str);
}

function styleLog(fullString, highlightedSubstrings, textColor, bgColor) {
    var textColorCode = "\x1b[38;2;" + textColor.join(";") + "m"; // Text color
    var bgColorCode = "\x1b[48;2;" + bgColor.join(";") + "m";     // Background color
    var resetCode = "\x1b[0m"; 
    
    var styledMessage = fullString;
    
    // Apply styling to each substring in the array
    highlightedSubstrings.forEach(function(highlightedSubstring) {
      var highlightedSubstringWithColors = textColorCode + bgColorCode + highlightedSubstring + resetCode;
      styledMessage = styledMessage.split(highlightedSubstring).join(highlightedSubstringWithColors);
    });
    
    console.log(styledMessage);
  }


  //----------------------end of beautifiers.js-------------------------------------
