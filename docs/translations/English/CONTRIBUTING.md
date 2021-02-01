# Contributing to KitHack

I thank you very much for the interest in wanting to contribute to this project. First of all, you need to review our [code of conduct](https://github.com/AdrMXR/KitHack/blob/master/docs/translations/English/CODE_OF_CONDUCT.md) as this ensures that our community acts positively and with the due respect that each of our potential collaborators deserves. In the event that the code of conduct is not being followed, any contribution you wish to make will be rejected without exception.

# Types of contributions

There are many ways you can contribute to KitHack, you don't need to know how to code to contribute. However, in most cases if certain technical knowledge is required, what is required as a primary requirement is knowing how to handle git correctly.

Some no-code contribution scenarios are as follows:

* **Report:** You can make a detailed report on any inconvenience or problem that is being presented in the tool and provide any solution or suggestion, it is necessary to include enough information for the total understanding of the problem, also make sure to comply with the expected code of conduct.
* **Documentation:** We always need new documentation and to correct certain grammatical errors or to replace old or little understandable information, you can collaborate in it with the objective that our documentation is totally of quality.
* **Tester:** Due to the constant updates, people are always required to test the changes in different systems to verify that everything works as it should. You can test the tool on any linux distribution that you have installed and report any inconvenience that occurs.
* **Participant:** You can support anyone in the [issues](https://github.com/AdrMXR/KitHack/issues) section and you can also help other collaborators to test their recently sent pull requests.

For those who want to contribute code, the first thing to do is set up a new development branch and make modifications to it so as not to affect the master branch. Once that is done and having verified that everything works correctly locally, they can now make the extraction request to be able to verify it.

Some code contribution scenarios are as follows:

* **Tools:** You can add new tools or remove obsolete tools. Before adding a tool, you must verify that it works correctly, you must also identify the type of tool to catalog it in the KitHack menu (Android, Windows, Phishing, etc ...). Once taking that into account, you must first work with the file [kitools.py](https://github.com/AdrMXR/KitHack/blob/master/lib/kitools.py), it must be positioned in the last tool of the category your tool belongs to and add its installation function below. Subsequently, you need to work with the [KitHack.py](https://github.com/AdrMXR/KitHack/blob/master/KitHack.py) file, identify its corresponding menu and add a short description of the tool you want to add and finally call the function. To delete tools that are obsolete or no longer exist, you must remove both the function in the file [kitools.py](https://github.com/AdrMXR/KitHack/blob/master/lib/kitools.py), and the description and the function call in the file [KitHack.py](https://github.com/AdrMXR/KitHack/blob/master/KitHack.py).
* **Backdoors:** You can add any feature or novelty to the backdoors generator, you can add new payloads or even exploits.
* **Refactoring:** You can also contribute with the reorganization of the code in KitHack, this case would be one of the most complex, therefore if you are determined to do it, contact us to work together.
* **New dependencies:** If you think a new dependency is needed or needs to be replaced, you can easily make the modification and explain the details in the pull request.
* **Bug:** If you have identified a code bug and think you can fix it, please do so and make a report to understand the nature of the problem.

**Important**: When you are going to make a pull request, it is necessary that you comply with the following points:

* Specify a descriptive title to facilitate understanding of your request.
* Include as much detail as possible.
* Include references
* Include instructions, advice or suggestions
* Include documentation