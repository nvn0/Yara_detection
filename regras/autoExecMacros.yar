rule Office_doc_AutoOpen
{
	meta:
		description = "Detecs Microsoft Office documents with strings related to macro code and AutoExecution."
	strings:
		$auto1 = "AutoOpen"
		$auto2 = "AutoClose"
		$macro = "ThisDocument"
		$macro2 = "Project"
	condition:
		uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and all of ($macro*) and 1 of ($auto*)
}