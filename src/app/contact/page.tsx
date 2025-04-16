export default function ContactPage() {
  return (
    <div className="font-[family-name:var(--font-fira-code)] mb-10 mt-20">
      <h1 className="text-4xl font-bold text-center font-[family-name:var(--font-belanosima)] uppercase">
        Contact Us
      </h1>
      <p className="text-center mt-4">We'd love to hear from you!</p>
      <form className="max-w-lg mx-auto mt-5 p-6">
        <div className="mb-4">
          <label
            className="block mb-2"
            htmlFor="name"
          >
            name
          </label>
          <input
            className="w-full p-2 border border-gray-300 rounded backdrop-blur-xl dark:border-gray-600"
            type="text"
            id="name"
            required
          />
        </div>
        <div className="mb-4">
          <label
            className="block mb-2"
            htmlFor="email"
          >
            email
          </label>
          <input
            className="w-full p-2 border border-gray-300 rounded backdrop-blur-xl dark:border-gray-600"
            type="email"
            id="email"
            required
          />
        </div>
        <div className="mb-4">
          <label
            className="block mb-2"
            htmlFor="message"
          >
            message
          </label>
          <textarea
            className="w-full p-2 border border-gray-300 rounded backdrop-blur-xl dark:border-gray-600"
            id="message"
            rows={4}
            required
          ></textarea>
        </div>
        <button className="bg-blue-500 text-white py-2 px-4 rounded hover:bg-blue-600 focus:outline-none focus:ring focus:ring-blue-300">
          Send Message
        </button>
      </form>
    </div>
  );
}
