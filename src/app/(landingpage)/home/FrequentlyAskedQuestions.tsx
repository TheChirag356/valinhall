import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import SectionHeader from "@/app/(landingpage)/home/SectionHeader";

export default function FrequentlyAskedQuestions() {
  return (
    <div>
      <SectionHeader text="frequently asked questions" />
      <Accordion type="single" collapsible className="w-full px-30 py-10">
        {faq.map((item, index) => (
          <AccordionItem value={`item-${index + 1}`} key={index}>
            <AccordionTrigger>{item.question}</AccordionTrigger>
            <AccordionContent>{item.answer}</AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  );
}

const faq = [
  {
    question: "Is source code required for Valinhall to function?",
    answer:
      "No, Valinhall does not require source code to function. It is a black-box scanner that tests your application from the outside, just like a real attacker would.",
  },
  {
    question: "How does Valinhall work?",
    answer:
      "Valinhall uses a combination of static and dynamic analysis to identify vulnerabilities in your application. It simulates real-world attacks to find security weaknesses.",
  },
  {
    question: "What types of vulnerabilities can Valinhall find?",
    answer:
      "Valinhall can find a wide range of vulnerabilities, including SQL injection, cross-site scripting (XSS), cross-site request forgery (CSRF), and more.",
  },
  {
    question: "Is Valinhall easy to use?",
    answer:
      "Yes, Valinhall is designed to be user-friendly and easy to navigate. It provides clear instructions and guidance throughout the scanning process.",
  },
  {
    question: "Can Valinhall be integrated with other tools?",
    answer:
      "Yes, Valinhall can be integrated with various CI/CD tools and security platforms to streamline your security testing process.",
  },
];
