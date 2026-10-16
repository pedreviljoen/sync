---
theme: ./nile-theme.json
author: Pedre Viljoen
date: MMMM dd, YYYY
paging: Slide %d / %d
---

# Minds meet

> Some nuggets and takeaways from the Amazon jungle

1. Amazon -> What, Why and How?
2. Engineering at scale
3. Some wow engineering nuggets
4. AI - Aritificial or Actual Intelligence

---

# Amazon

> What, Why and How?

Managed Fleets was a organisation about 10 years ago, aimed to provide fleet management for internal teams needing hosts in data centers.

FYI: A region is made up of 3 Availability Zones (AZs), an AZ is made up of 3 datacenters. With some regulatory specs:

- Independent power
- Independent internet
- AZs ping between each other < 5ms
- Investment cost ~$2 billion

```
                    REGION

                  ┌─────────┐
                  │   D1    │
                  │  /  \   │
                  │ D2--D3  │
                  │  AZ-a   │
                  └─────────┘
                      / \
           ping     /     \  ping
           <5ms   /         \  <5ms
                /             \
      ┌─────────┐             ┌─────────┐
      │   D1    │             │   D1    │
      │  /  \   │             │  /  \   │
      │ D2--D3  │─────────────│ D2--D3  │
      │  AZ-b   │  ping<5ms   │  AZ-c   │
      └─────────┘             └─────────┘
```

The term `Managed` is a philosophy born inside Amazon. Don't let your customers own the tools you've built, own it yourself.

---

# Amazon

> continued... How?

```
┌──────────┐   jobs    ┌──────────┐   tasks   ┌─────────────────────┐
│ DynamoDB │──────────▶│ AWS SWF  │──────────▶│       Worker        │
│          │           │          │           │                     │
│ records  │◀──────────│ pick up  │◀──────────│  Launch EC2         │
└──────────┘  update   └──────────┘   done    │       │             │
                                              │       ▼             │
                                              │  Provision network  │
                                              │       │             │
                                              │       ▼             │
                                              │  Register DNS       │
                                              │       │             │
                                              │       ▼             │
                                              │  Register AuthZ     │
                                              │       │             │
                                              │       ▼             │
                                              │  Update records     │
                                              └─────────────────────┘
```

---

# Engineering at Scale

> Some fascinating engineering at Scale scenarios

## CMDB - cellularised

```
           REGION  ·  4–8 cells
┌────────────┬────────────┬────────────┐
│    AZ-a    │    AZ-b    │    AZ-c    │
│  ┌──┐ ┌──┐ │  ┌──┐ ┌──┐ │  ┌──┐ ┌──┐ │
│  │C1│ │C2│ │  │C3│ │C4│ │  │C5│ │C6│ │
│  └──┘ └──┘ │  └──┘ └──┘ │  └──┘ └──┘ │
└────────────┴────────────┴────────────┘

         traffic routed to cells
         blast radius of impact limited to cell

   Regional           Zonal        Zonal-Cellular
┌───┬───┬───┐   ┌───┬───┬───┐   ┌───┬───┬───┐
│███│███│███│   │███│   │   │   │█  │   │   │
│███│███│███│   │███│   │   │   │   │   │   │
└───┴───┴───┘   └───┴───┴───┘   └───┴───┴───┘
 whole region     one AZ          one cell
```

## Pipelines

```
┌──────────┐      ┌────────────────────────────────────┐
│  CANARY  │      │              PIPELINE              │
│  metrics │      │                                    │
│          ├─────▶│  ┌────────┐  ┌────────┐  ┌────────┐│
│ approval │      │  │ Stage 1│─▶│ Stage 2│─▶│ Stage n││
│  step    │      │  │ target │  │ target │  │ target ││
│          │      │  └────────┘  └────────┘  └────────┘│
└──────────┘      └─────────────────┬──────────────────┘
                                    │
                             wave function
                      chooses each stage target
                      to minimise blast radius

 A stage target is one of:

   Regional           Zonal        Cellular-Zonal
┌───────────┐   ┌───┬───┬───┐   ┌───┬───┬───┐
│███████████│   │███│   │   │   │█  │   │   │
└───────────┘   └───┴───┴───┘   └───┴───┴───┘

 Canary
 non-prod load → metrics
```

---

# Engineering at Scale

> continued...

## Throttling

```
 Token bucket  (per node)

  request ──▶ ┌─────────────────┐ ──▶ allow
              │  ●  ●  ●  ●  ○  │
              └────────▲────────┘
                       │ refill


 Gossip  ·  nodes share remaining tokens

 ┌─────────┐     gossip     ┌─────────┐
 │ Node A  │◀──────────────▶│ Node B  │
 │  ●●●●   │     ● ●        │  ○○○○   │
 └────┬────┘                └────┬────┘
      │         gossip           │
      └────────────┬─────────────┘
                   ▼
             ┌─────────┐
             │ Node C  │
             │  ●●○○   │
             └─────────┘
```

## Fun fact
  - Our MF org launched and deprovisioned about 1 billion instances a week
  - IAM: Identity and Access Management service
  - Global in IAD, runs on about 1500-2000 single-slotter hosts (192 cores and 384GB memory per host)

---

# 2 Engineering Nuggets

> Two things which really blew my mind from an engineering perspective

1. Live migrations
2. Precision clock

## Live migrations

Some clever folsk in (guess where), built this.

Each droplet is virtualised and state of vCPUs is kept on a rack. Once a droplet becomes "hot", ie. 80-90% if vCPUs subscribed. Live migrations, pauses the CPU clock copies CPU cache and virtual memory state to another droplet and resumes your running process and ec2 instance on another droplet... all under 100ns.

## Precision clock

Time is really important inside datacenters, AZs and regions. Drives core logic:

- IAM creds
- Database replica sync
  - In-region and across-region
- Recovery of redundant EBS snapsnots (point in time)
- Logs and metrics

So much so, that Amazon launched a satelite network which synchronises the machine clocks globally... it cost more than $1 billion.

---

# AI - Aritificial or Actual Intelligence

## AI at Amazon

> Some interesting observations into how AI is utilised internally and key takeaways

- Unlimited AI budget -> dedicated rack of servers running Antropic and OpenAI models, such to not consume compute from Bedrock used by external customers
- Kiro
- AgentSpaces
- AI steering and spec-driven development

## AI takeaways

Not here to make predictions, it is difficult to tell what the state of `AI` will be in 3-6-12 months from now.

It has an amplifying effect:

- In the hands of a good engineer with proper steering and context -> great outcomes
- The inverse is also true -> experienced this first hand at Amazon with a lot of AI slop being churned out

`AI` models will get better, a lot. Context management, security protocols, tight steering and validation loops can drive automated `AI` infrastructure.

---

## AI takeaways

> continued...

Some things I found useful:

- Grill me skill (matt pocock)
  - Use it to poke holes in your idea, make it bulletproof. Don't let the `AI` make assumption decisions for you.
- When you do something repetitive once with `AI`, after you done... ask the agent to write you a skill to do it next time, keep this up to date
- Understand the strength and weaknesses of models, and adapt to them as they change

```
┌─────────────────────────────────────────────────────┐
│ 2022-24   PROMPT     one message                    │
└──────────────────────────┬──────────────────────────┘
                           v
┌─────────────────────────────────────────────────────┐
│ Jun 2025  CONTEXT    one session                    │
│           files, history, tool results              │
└──────────────────────────┬──────────────────────────┘
                           v
┌─────────────────────────────────────────────────────┐
│ Feb 2026  HARNESS    one agent run                  │
│           tools, sandbox, tests, permissions        │
└──────────────────────────┬──────────────────────────┘
                           v
┌─────────────────────────────────────────────────────┐
│ Jun 2026  LOOP       many runs                      │
│           when, on what, who stops it?              │
└─────────────────────────────────────────────────────┘
```

- System One models
  - Watch this space, try to make your `AI` setup more efficient with it
- Rule #1, don't forget to think

---

# Questions?
