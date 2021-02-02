# Contribuyendo a KitHack

Agradezco mucho por el interes de querer contribuir en este proyecto. Antes que nada es necesario que revises nuestro [código de conducta](https://github.com/AdrMXR/KitHack/blob/master/docs/CODE_OF_CONDUCT.md) ya que esto nos garantiza que nuestra comunidad actúe de manera positiva y con el debido respeto que se merece cada uno de nuestros posibles colaboradores. En caso de que no se este cumpliendo el código de conducta, cualquier contribución que desees realizar será rechazada sin excepción alguna.

# Tipos de contribuciones

Hay muchas formas de poder contribuir en KitHack, no es necesario saber programar para poder contribuir. Sin embargo, en la mayoría de los casos si se requiere de ciertos conocimientos técnicos, lo que si se requiere como requisito primordial es saber manejar correctamente git.

Algunos escenarios de contribución sin código son los siguientes:

* **Reporte:** Usted puede realizar un informe detallado sobre cualquier inconveniente o problema que se este presentando en la herramienta y proporcionar alguna solución o sugerencia, es necesario que incluya información suficiente para la comprensión total del problema, asegurese también de cumplir con el código de conducta esperado. 
* **Documentación:** Siempre se necesita de nueva documentación y de corregir ciertos errores gramaticales o de reemplazar información vieja o poco entendible, usted puede colaborar en ello con el objetivo de que nuestra documentación sea totalmente de calidad. 
* **Tester:** Debido a las constantes actualizaciones, siempre se requiere de personas que testeen los cambios en diferentes sistemas para comprobar de que todo funcione como se debe. Usted puede testear la herramienta en cualquier distribución linux que tenga instalada y reportar cualquier inconveniente que se logre presentar.
* **Participante:** Puede apoyar a cualquier persona en el apartado de [issues](https://github.com/AdrMXR/KitHack/issues) y también puede ayudar a otros colaboradores a probar sus solicitudes de extracción recien enviadas.

Para los que deseen contribuir con código, lo primero que tienen que hacer es configurar una nueva rama de desarrollo y hacer las modificaciones en ella para no afectar a la rama maestra. Una vez hecho eso y de haber comprobado que todo funcione correctamente de manera local, ya pueden hacer la solicitud de extracción para poder verificarla.

Algunos escenarios de contribución con código son los siguientes:

* **Herramientas:** Usted puede agregar nuevas herramientas o eliminar herramientas obsoletas. Antes de agregar una herramienta, debe verificar que esta funcione de manera correcta, también debe identificar el tipo de herramienta para catalogarla en el menú de KitHack (Android, Windows, Phishing, etc...). Una vez teniendo en cuenta eso, debe trabajar primero con el archivo [kitools.py](https://github.com/AdrMXR/KitHack/blob/master/lib/kitools.py), debe posicionarse en la ultima herramienta de la categoría a la que corresponde su herramienta y agregar su función de instalación debajo. Posteriormente, debe trabajar con el archivo [KitHack.py](https://github.com/AdrMXR/KitHack/blob/master/KitHack.py), identificar su menú correspondiente y agregar una pequeña descripción de la herramienta que desea agregar y finalmente mandar a llamar la función. Para borrar herramientas obsoletas o que ya no existen, debe eliminar tanto la función en el archivo [kitools.py](https://github.com/AdrMXR/KitHack/blob/master/lib/kitools.py), como la descripción y la llamada de la función en el archivo [KitHack.py](https://github.com/AdrMXR/KitHack/blob/master/KitHack.py).
* **Backdoors:** Usted puede agregar cualquier caracteristica o novedad al generador de puertas traseras, puede agregar nuevos payloads o incluso exploits.
* **Refactorización:** También puede contribuir con la reorganización del código en KitHack, este caso sería uno de los más complejos, por ende si esta decidido a hacerlo, contactenos para trabajar en conjunto.
* **Nuevas dependencias:** Si usted cree que se necesita de alguna nueva dependencia o se requiere reemplazar alguna, puede hacer la modificación sin problemas y explicar los detalles en la solicitud de extracción.
* **Bug:** Si ha identificado un error de código y cree poder solucionarlo, hagalo y realice un reporte para poder comprender la naturaleza del problema.

**Importante**: Cuando vaya a realizar una solicitud de extracción, es necesario que cumpla con los siguientes puntos:

* Especifique un titulo descriptivo para facilitar la comprensión de su solicitud.
* Incluya todos los detalles posibles.
* Incluya referencias
* Incluya instrucciones, consejos o sugerencias
* Incluya documentación