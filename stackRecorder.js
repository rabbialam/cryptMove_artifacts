class StackEntry
{
    constructor(name)
    {
        this.__name = name;
        this.__count = 0;
        
        
    }

    getOrCreateChild(name)
    {
        if (!(name in this))
        {
            this[name] = new StackEntry(name);
        }
        return this[name];
    }

    toString()
    {
        return this.__name + " - " + this.__count;
    }
    toJSON() {
        const jsonRepresentation = {
            name: this.__name,
            count: this.__count
        };

        // Recursively convert child StackEntry instances to JSON
        for (const key in this) {
            if (this[key] instanceof StackEntry) {
                jsonRepresentation[key] = this[key].toJSON();
            }
        }

        return jsonRepresentation;
    }
}

var stackRoot = new StackEntry("root");

var bpList = [];

function populateBpList(filePath) {

    ///var logFilePath = "c:\\debugging\\output\\output.log";

   try {
       log(filePath)
        var file = host.namespace.Debugger.Utility.FileSystem.OpenFile(filePath);
        var textReader = host.namespace.Debugger.Utility.FileSystem.CreateTextReader(file, 'Ascii');

        while (!textReader.EndOfStream) {
            bpList.push(textReader.ReadLine());
        }

        textReader.Close();
        file.Close();
    } catch (error) {
        host.diagnostics.debugLog("Error reading file: " + error + "\n");
    }
}


function onBreakpoint()
{
    var node = stackRoot;
    for (var frame of host.namespace.Debugger.State.DebuggerVariables.curstack.Frames)
    {
        var sourceInfo = frame.Attributes.SourceInformation;
        var offset =  sourceInfo.FunctionAddress + sourceInfo.FunctionOffset -sourceInfo.Module.BaseAddress;
        //log(offset);
        //log(sourceInfo.Module.Symbols.Name)
        var mode= sourceInfo.Module.Symbols.Name+'!'+offset;
        node = node.getOrCreateChild(mode);
        node.__count++;
    }
}

function resetStackTraces()
{
    stackRoot = new StackEntry();
}
function fileWrite(output,logFilePath) {

    ///var logFilePath = "c:\\debugging\\output\\output.log";
    log("in file write");
    log(logFilePath);
    var logFile;
    var fileExists = host.namespace.Debugger.Utility.FileSystem.FileExists(logFilePath);
    

    if (fileExists) {        
        log("openinnig existing file")
       // logFile.Seek(0, 2);
       logFile = host.namespace.Debugger.Utility.FileSystem.OpenFile(logFilePath);
    }
    else {        
        log("creating new file")
        logFile = host.namespace.Debugger.Utility.FileSystem.CreateFile(logFilePath);
    }
    log("file open");
    var textWriter = host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(logFile, "Ascii");

    try {
        
        for (var line of output.split("\n")){
            log(line);
            textWriter.WriteLine(line);
        }
        
        
    }catch (error) {
        host.diagnostics.debugLog("Error writting file: " + error + "\n");
        
    }finally{
        textWriter.Close();
        logFile.close();
    }
    
}
function setBreakPoint(address){
    log("setting break point")
    let breakpointCommand = `bp  ${address} "dx @$scriptContents.onBreakpoint(); g;"`
    log(breakpointCommand)
    var res = exec(breakpointCommand);
    log(res)
}

function log(message) {
    // Helper function for logging messages
    host.diagnostics.debugLog(message + "\n");
}

function exec(command) {
    // Helper function for executing Windbg commands
    var control = host.namespace.Debugger.Utility.Control;
    var output = control.ExecuteCommand(command); // 'k' is the command to display the call stack
    return output;

}
function initializeScript()
{
    // Add code here that you want to run every time the script is loaded. 
    // We will just send a message to indicate that function was called.
    
    host.diagnostics.debugLog("***> initializeScript was called\n");
}
function invokeScript()
{

    // Add code here that you want to run every time the script is executed. 
    // We will just send a message to indicate that function was called.
	    //setBreakpointAndPrintStackTrace("aes_ni_256_e", "C:\\\\log\\\\callstack.txt");
    //log("init");
      //  log("base "+addr);
        // log("Base "+host.evaluateExpression("KERNEL32!BaseThreadInitThunk"));
	var filePath = "C:\\Users\\malam5\\source\\repos\\ConsoleApplication3\\kerberosbp.txt";
    //var filePath = "C:\\Users\\malam5\\source\\repos\\ConsoleApplication3\\plink_debug_function";
	populateBpList(filePath);
	for (var bp of bpList){
		setBreakPoint(bp);
	}
    //setBreakPoint("aes_ni_256_e");
    host.diagnostics.debugLog("***> invokeScript was called\n");
}
function uninitializeScript()
{
    // Add code here that you want to run every time the script is unloaded. 
    // We will just send a message to indicate that function was called.
    const jsonString = JSON.stringify(stackRoot.toJSON(), null, 2);
    var logFile = "C:\\Users\\malam5\\source\\repos\\ConsoleApplication3\\kerberos_encrypt_stack.txt";

    //log(jsonString);
    fileWrite(jsonString,logFile);
    host.diagnostics.debugLog("***> uninitialize was called\n");
}