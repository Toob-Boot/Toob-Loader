---
description: Used to plan a spec-driven implementation of a certain file
---

The goal of this prompt is to optimze your context-window in order to create the best possible plan of developing a given file. By reading Spec-Files.

Gather your context through ALL files according to the following:

In the top of the files we're working with, there is always a list of linked or related specs. If not report so. Take these plus the major one's like concept_fuion.md and sometimes hals.md in order to collect context. And whatever else you want to look at before you continue.

After that:

- Context:

Read all the files mentioned or discussed in the current context of the conversation.

Since LLMs have the highest attentions of conversation-context in the beginning and end of the context, we try to get the most relevant context for developing complex software to the most recent history of the Context window in order to achieve better code.

- Instruction:

Read each file from top to bottom. If a file is longer than 800L, you need to manually read the next part until you hit the actual file end. DO NOT skip parts just because you think you remember con

Gather every Context regarding our targeted file.

With all of this good context, you now create an optimal and complete implementation plan for the given file. Do not forget stuff. Look at everything and create the best plan.
