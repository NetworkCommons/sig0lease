+++
title = 'Insights into sig0lease development'
layout = 'posts'
date = 2024-04-10T11:12:15+02:00
draft = false
#featured_image = '/images/mycosystem-quarter.jpg'
featured_image = ""
toc = false
+++

_(Ed: This article is written by team member Stefano Bocconi, with many years of development experience across various environments, including technical development roles within several large scale European projects)._

This blog is a reflection on my experience with AI coding agents half-way through the sig0lease project funded by PTF.

It also aims to give more nuances to the apparent dilemma of nowadays developer: do I write the code, or do I let an agent do it for me (and then I should review what the agent has done, I have learnt that this step is not always performed).

At the beginning I was very curious about the possibility of coding agents, and I wanted to experiment with running a local LLM (the brain of a coding agent) on my laptop, using an open-weight model. Apart from being educational, this experiment saves subscription money paid to the various providers such as Anthropic, OpenAI, etc.

Online there were several articles and tutorials that sounded very positive about running your own LLM, and several tools to do so, the most famous of which are [Ollama](https://ollama.com/) and [LM Studio](https://lmstudio.ai/) (but also [mlx-serve](https://mlxserve.com/) for Mac).

These tools allow you to pull a model (for example, one of the Qwen family created by AliBaba, good for coding tasks) from their repository  and run it locally.

Although my laptop has 64 GB of RAM - which I would normally consider an enormous amount of memory - I soon realised that these LLMs require an even larger amount of it.

To give the reader an idea of the memory consumption of an LLM (leaving aside an overhead of about 20%), the use is due to 2 main factors:

- the number of parameters (weights)

  - *memory = nr parameters x bytes per parameter*

- the KV (Key-Value) cache:

  - Transformers (the tech of every modern LLM) use what is called an attention mechanism, that store 2 vectors (the Key vector and the Value vector) for every single token processed (this is done to avoid repeating the same calculations, therefore the name KV-cache), for each layer of the transformer.

  - The number of tokens processed is called the context length of an LLM (very important factor), and each token is numerically represented by a vector. So the memory requirements are:  
	*memory = 2 x nr layers transformer x size 1 token x context length*

So for a 70 Billion parameter model, using precision FP16 for the parameters (2 bytes/parameter), and with a context length of 128,000 tokens this would be about 200 GB of memory, much more than my laptop can handle.

This is why a couple of tricks were introduced to reduce the memory requirement. The most popular of which is to reduce the precision of the parameters from FP16 (2 bytes) to INT8 (one byte) or also INT4 (½ byte). With INT4 quantisation the same model as above would require about 70 GB, still a lot.

But do we need to have a 70B model with 128K of context length? I found the many tutorials and article on-line very optimistic about models with less parameters and a shorter context-length, so I experimented with those.

After numerous trial and errors, and unexpected Out Of Memory crashes I settled for a model with 35B and INT4 quantisation, reducing the context-length to 32K, more or less the maximum that was stable enough to be used.

The problem of a reduced context-length can be understood if we think that the context in an interaction with a coding agent contains all of your questions (prompts), all of the agent replies, and for example all the code the agent has looked at if you asked to improve the code in a repository.

In my experience an insufficient context-length is not a problem at the beginning, but if your conversation is long enough and/or the repository you are working on is big enough, soon the context-length is reached and the agent starts throwing away information. There are several strategies, one of which is to throw the tokens in the middle, assuming what you asked at the beginning and what you most recently asked represent the most important pieces of information.

Even though an agent should be ‘conscious’ of the fact that the context is filling up and compact it with summarisation, this did not work well in my local setting. I observed a behaviour similar to an Alzheimer patient, repeating the same thing over time, forgetting previous decisions, etc.

So after much struggle, I switched to a paid subscription. It is now much better: a faster, more accurate, more “intelligent” experience. I hope at some point to return to experimenting with local models, because there are new improved models and tool releases almost every day.

In any case, I have witnessed the advent of coding agents has brought a clear change in how software is written, in my coding as well as in the coding of some colleagues.

Although developers might be delegating more or less of the coding responsibilities to agents, (some developers have **totally** delegated theirs), I think that the common aspects are the following:

- Creation speed: code is produced at a much higher speed than manual coding. You ask, and you will get.

- Ideally, you want to check the code that is written, and in my opinion you **need** to do so. But once the agent has completed a task, you easily see that you would want some changes, or some improvements, or the results are not quite what you wanted. Basically you can be stuck in a mode of continuously asking for more. The code is always changing, and as soon as you start checking one part, that part has been rewritten following your requests. The code changes under your nose.

- The time is spent much more in guiding the agent towards a goal, than coding or checking. Because what is the point of checking the code if it does not yet do what you want? You must review as much as it is needed to verify your instructions have been followed.

- Often your instructions have not been followed. Maybe very expensive models understand requests and code accordingly, but this is not my experience with the models I am using. Therefore much attention must be directed to **testing**, to be absolutely sure that the code has a good chance to be correct, and can be finally inspected. Funnily enough, tests are also generated by the agent, so you can be fooled while you are thinking that you are smart. I made a point to **thoroughly check the test scripts** as I needed to be sure I had a reference point I could trust. The tests were OK, but I made lots of changes to ensure they really were scoped to align with what I believed they should be. But I have to admit that the starting point was good, so … well done agent!

Of course, the more explorative and less defined the task is, the more the agent will make its own choices and assumptions which are likely misguided and wrong. Agents are trained to please, and they tend to remove the burden of thinking from the developer. This is especially critical when the actual situation is more complex than the agent presents. And that risk of misguided or misleading simplifications is something to be constantly vigilant and on the look-out for.


  

