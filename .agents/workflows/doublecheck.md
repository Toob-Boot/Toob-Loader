---
description: Used for checking the implementation of a code file developed in a spec-driven manner
---

The goal of this prompt is to optimze your context-window in order to analyze a given and already written code file in order to not forget anything the specs mentioned. Also checking for faulty implementations.

Gather your context through ALL files according to the following:

In the top of the files we're working with, there is always a list of linked or related specs. If not report so. Take these plus the major one's like concept_fuion.md and sometimes hals.md in order to collect context. And whatever else you want to look at before you continue.

After that:

- Context:

Read all the files mentioned or discussed in the current context of the conversation.

Since LLMs have the highest attentions of conversation-context in the beginning and end of the context, we try to get the most relevant context for developing complex software to the most recent history of the Context window in order to achieve better code.

- Instruction:

Read each file from top to bottom. If a file is longer than 800L, you need to manually read the next part until you hit the actual file end. DO NOT skip parts just because you think you remember con

Gather every Context regarding our targeted file.

Having done that, you now have to do this:

Please scan all related specs-documents.

Look for forgotten implementations or missing features, that might be described, but not implemented or mentioned as a clear TODO.
DO NOT forget or misprioritize certain features. Everything is 100% needed and missing features that might get forgotten are hazardous.

Mark every not implemented feature OR dummy-implementation etc. as a clear "TODO".

Please work as detail-driven and correct as possible in order to achieve the best code-quality of the given file.
