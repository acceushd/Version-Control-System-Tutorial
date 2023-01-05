package svcs

import java.io.*
import java.io.File.separatorChar
import java.math.BigInteger
import java.security.MessageDigest
import kotlin.io.*

private val commands = mapOf(
    "config" to "Get and set a username.",
    "add" to "Add a file to the index.",
    "log" to "Show commit logs.",
    "commit" to "Save changes.",
    "checkout" to "Restore a file."
)

const val HELP = "These are SVCS commands:\n" +
        "config     Get and set a username.\n" +
        "add        Add a file to the index.\n" +
        "log        Show commit logs.\n" +
        "commit     Save changes.\n" +
        "checkout   Restore a file."

val COMMITS_DIRECTORY = "vcs${separatorChar}commits"
val INDEX_FILE = "vcs${separatorChar}index.txt"
val CONFIG_FILE = "vcs${separatorChar}config.txt"
val LOG_FILE = "vcs${separatorChar}log.txt"
val FILE_DIRECTORY = "vcs"


fun main(args: Array<String>) {
    val file = File(FILE_DIRECTORY).mkdirs()
    val configFile = File(CONFIG_FILE)
    val indexFile = File(INDEX_FILE)
    val commitFile = File(COMMITS_DIRECTORY).mkdir()
    val logFile = File(LOG_FILE).apply { createNewFile() }
    if (args.isNotEmpty()) {
        when (args[0]) {
            "config" -> config(inputOrNull(args), configFile)
            "--help" -> println(HELP)
            "add" -> add(inputOrNull(args), indexFile)
            "log" -> log(logFile)
            "commit" -> commit(logFile, configFile, indexFile, inputOrNull(args))
            "checkout" -> checkout(logFile, inputOrNull(args))
            else -> println("'${args[0]}' is not a SVCS command.")
        }
    } else println(HELP)
}

fun config(input: String?, configFile: File) {
    if (!configFile.exists() && input == null)
        println("Please, tell me who you are.")
    else if (!configFile.exists() && input != null) {
        configFile.createNewFile()
        configFile.writeText(input)
        val text = configFile.readText().trim()
        println("The username is $text.")
    } else if (configFile.exists() && input == null) {
        val text = configFile.readText().trim()
        println("The username is $text.")
    } else if (input != null) {
        configFile.writeText(input)
        val text = configFile.readText().trim()
        println("The username is ${text.trim()}.")
    }
}

fun add(input: String?, indexFile: File) {
    if (!indexFile.exists() && input == null)
        println("Add a file to the index.")
    else if (input != null) {
        if (!File(input).exists())
            println("Can't find '$input'.")
        else {
            indexFile.appendText("$input\n")
            println("The file '$input' is tracked.")
        }
    } else {
        println("Tracked files:")
        val text = indexFile.readLines()
        for (line in text)
            println(line)
    }
}

fun log(log: File) {
    if (log.readText().isEmpty())
        return println("No commits yet.")
    println(log.readText())
}

fun commit(log: File, config: File, index: File, message: String?) {
    if (message == null)
        return println("Message was not passed.")
    if (lastID(log) == currentID(index))
        return println("Nothing to commit.")
    val id = currentID(index)
    addToLog(config, id, message, log)
    println("Changes are committed.")
    val newDirectory = "$COMMITS_DIRECTORY${separatorChar}$id"
    val newDirectoryFile = File(newDirectory).mkdir()
    index.readLines().forEach { File(it).copyTo(File("$newDirectory${separatorChar}$it")) }
}

fun checkout(log: File, commitID: String?) {
    if (commitID == null) return println("Commit id was not passed.")
    val logLines = log.readText().split("\n")
    var commitExists = false
    logLines.forEach { if (it.startsWith("commit $commitID")) commitExists = true }
    if (!commitExists) return println("Commit does not exist.")
    val commitDir = File("$COMMITS_DIRECTORY${separatorChar}$commitID")
    commitDir.listFiles()?.forEach { it.copyTo(File(it.name), true) }
    println("Switched to commit $commitID.")
}

fun lastID(logFile: File): String {
    val lines = logFile.readLines()
    return if (lines.isEmpty())
        " "
    else
        lines.first().substringAfter(' ')
}

fun addToLog(config: File, id: String, commit: String, newLog: File) {
    val logs = newLog.readText()
    val author = config.readText()
    val commits = """
        commit $id
        Author: $author
        $commit
    """.trimIndent()
    newLog.writeText("$commits\n\n$logs")
}

fun currentID(index: File) = sha256(index.readLines().joinToString { File(it).readText() })

fun sha256(input: String): String {
    val md = MessageDigest.getInstance("SHA-256")
    val hash = md.digest(input.toByteArray())
    val hashInt = BigInteger(1, hash)
    return hashInt.toString(16).padStart(32, '0')
}

fun inputOrNull(args: Array<String>) = if (args.size == 2) args[1] else null