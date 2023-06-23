/*
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.utilities.ByteUtils;
import burp.api.montoya.utilities.Utilities;
import io.projectdiscovery.nuclei.gui.*;
import io.projectdiscovery.nuclei.gui.settings.SettingsPanel;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.TemplateUtils;
import io.projectdiscovery.nuclei.yaml.YamlUtil;
import io.projectdiscovery.utils.Utils;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class BurpExtender implements BurpExtension {

    private static final String GENERATE_CONTEXT_MENU_TEXT = "Generate template";

    private static final String GENERATOR_TAB_NAME = "Generator";

    private static final String EXTENSION_NAME = "Nuclei";

    private Map<String, String> yamlFieldDescriptionMap = new HashMap<>();
    private JTabbedPane nucleiTabbedPane;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName(EXTENSION_NAME);

        final Preferences persistenceContext = montoyaApi.persistence().preferences();

        final Logging logging = montoyaApi.logging();
        final GeneralSettings generalSettings = new GeneralSettings.Builder()
                .withOutputConsumer(logging::logToOutput)
                .withErrorConsumer(logging::logToError)
                .withExtensionSettingSaver(persistenceContext::setString)
                .withExtensionSettingLoader(persistenceContext::getString)
                .build();

        try {
            generalSettings.log("test");
            final UserInterface userInterface = montoyaApi.userInterface();
            userInterface.registerSuiteTab(EXTENSION_NAME, createConfigurationTab(generalSettings));

            initializeNucleiYamlSchema(generalSettings);

            userInterface.registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
                @Override
                public List<Component> provideMenuItems(ContextMenuEvent event) {
                    generalSettings.log("provideMenuItems");
                    return createContextMenuItems(event, generalSettings, montoyaApi.utilities())
                            .stream()
                            .map(contextMenuItem -> (Component) contextMenuItem)
                            .collect(Collectors.toList());
                }

            });
        } catch (Throwable e) {
            JOptionPane.showMessageDialog(null, "There was an error while trying to initialize the plugin. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
            generalSettings.logError("Error while trying to initialize the plugin", e);
        }
    }

    private List<JMenuItem> createContextMenuItems(ContextMenuEvent event, GeneralSettings generalSettings, Utilities utilities) {
        List<JMenuItem> menuItems = Collections.emptyList();

        final List<HttpRequestResponse> httpRequestResponses = event.selectedRequestResponses();
        final ByteUtils byteUtils = utilities.byteUtils();

        try {
            if (httpRequestResponses.isEmpty()) {
                menuItems = createContextMenuItems(event, generalSettings, httpRequestResponses, byteUtils);
            } else if (httpRequestResponses.size() > 1) {
                menuItems = createMultiSelectionContextMenuItems(generalSettings, httpRequestResponses, byteUtils);
            } else {
                menuItems = createContextMenuItems(event, generalSettings, httpRequestResponses, byteUtils);
            }
        } catch (MalformedURLException e) {
            generalSettings.logError(e.getMessage());
        }
        return menuItems;
    }

    private List<JMenuItem> createContextMenuItems(ContextMenuEvent event, GeneralSettings generalSettings, List<HttpRequestResponse> httpRequestResponses, ByteUtils byteUtils) throws MalformedURLException {
        final List<JMenuItem> menuItems;

        final Optional<MessageEditorHttpRequestResponse> messageEditorHttpRequestResponse = event.messageEditorRequestResponse();
        if (messageEditorHttpRequestResponse.isPresent()) {
            final HttpRequestResponse requestResponse = messageEditorHttpRequestResponse.get().requestResponse();
            final Optional<Range> selectionRange = messageEditorHttpRequestResponse.get().selectionOffsets();
            menuItems = createSingleSelectionContextMenuItems(event, requestResponse, selectionRange.orElseGet(EmptyRange::new), generalSettings, byteUtils);
        } else {
            menuItems = createSingleSelectionContextMenuItems(event, httpRequestResponses.get(0), new EmptyRange(), generalSettings, byteUtils);
        }

        return menuItems;
    }

    @NotNull
    private List<JMenuItem> createMultiSelectionContextMenuItems(GeneralSettings generalSettings, Collection<HttpRequestResponse> httpRequestResponses, ByteUtils byteUtils) throws MalformedURLException {
        final String[] requests = httpRequestResponses.stream()
                                                      .map(HttpRequestResponse::request)
                                                      .map(HttpMessage::toByteArray)
                                                      .map(ByteArray::getBytes)
                                                      .map(byteUtils::convertToString)
                                                      .toArray(String[]::new);

        final Requests templateRequests = new Requests();
        templateRequests.setRaw(requests);
        final HttpRequestResponse firstHttpRequestResponse = httpRequestResponses.stream().findFirst().get(); // TODO pass in all the unique targets
        final URL targetURL = new URL(firstHttpRequestResponse.request().url());
        final List<JMenuItem> menuItems = new ArrayList<>(List.of(createContextMenuItem(() -> generateTemplate(generalSettings, targetURL, templateRequests), GENERATE_CONTEXT_MENU_TEXT)));

        final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, requests);
        if (!addToTabMenuItems.isEmpty()) {
            final JMenu addRequestToTabMenu = new JMenu("Add request to");
            addToTabMenuItems.forEach(addRequestToTabMenu::add);
            menuItems.add(addRequestToTabMenu);
        }
        return menuItems;
    }

    private List<JMenuItem> createSingleSelectionContextMenuItems(ContextMenuEvent event, HttpRequestResponse httpRequestResponse, Range selectionRange, GeneralSettings generalSettings, ByteUtils byteUtils) throws MalformedURLException {
        List<JMenuItem> menuItems = Collections.emptyList();

        final HttpRequest httpRequest = httpRequestResponse.request();
        final byte[] requestBytes = httpRequest.toByteArray().getBytes();

        final URL targetUrlWithPath = new URL(httpRequest.url());
        final URL targetUrl = new URL(targetUrlWithPath.getProtocol(), targetUrlWithPath.getHost(), targetUrlWithPath.getPort(), "/");


        generalSettings.log("invocation type:" + event.invocationType());

        if (event.isFromTool(ToolType.INTRUDER)) {
            final String request = byteUtils.convertToString(requestBytes);
            generalSettings.log("intuder");
            menuItems = generateIntruderTemplate(generalSettings, targetUrl, request);
        } else {
            if (event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST) || event.isFrom(InvocationType.MESSAGE_VIEWER_REQUEST)) {
                generalSettings.log("message editor request");
                menuItems = createMenuItemsFromHttpRequest(generalSettings, targetUrl, requestBytes, selectionRange, byteUtils);
            } else if (event.isFrom(InvocationType.MESSAGE_EDITOR_RESPONSE) || event.isFrom(InvocationType.MESSAGE_VIEWER_RESPONSE)) {
                generalSettings.log("message editor response");
                menuItems = createMenuItemsFromHttpResponse(generalSettings, targetUrl, httpRequestResponse, selectionRange, byteUtils);
            }
        }
        return menuItems;
    }

    private void initializeNucleiYamlSchema(GeneralSettings generalSettings) {
        this.yamlFieldDescriptionMap = SchemaUtils.retrieveYamlFieldWithDescriptions(generalSettings);
        if (this.yamlFieldDescriptionMap.isEmpty()) {
            generalSettings.logError("AutoCompletion will be disabled, because there was an error while downloading, accessing or parsing the nuclei JSON schema.");
        } else {
            generalSettings.log("JSON schema loaded and parsed!");
        }
    }

    private Component createConfigurationTab(GeneralSettings generalSettings) {
        final JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Configuration", new SettingsPanel(generalSettings));
        tabbedPane.setVisible(true);

        this.nucleiTabbedPane = tabbedPane;
        return tabbedPane;
    }

    private List<JMenuItem> createMenuItemsFromHttpRequest(GeneralSettings generalSettings, URL targetUrl, byte[] requestBytes, Range selectionRange, ByteUtils extensionHelpers) {
        final String request = extensionHelpers.convertToString(requestBytes);

        final JMenuItem generateTemplateContextMenuItem = createTemplateWithHttpRequestContextMenuItem(generalSettings, requestBytes, targetUrl);
        final JMenuItem generateIntruderTemplateMenuItem = createIntruderTemplateMenuItem(generalSettings, targetUrl, request, selectionRange);

        final List<JMenuItem> menuItems = new ArrayList<>(Arrays.asList(generateTemplateContextMenuItem, generateIntruderTemplateMenuItem));

        final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, new String[]{request});
        if (!addToTabMenuItems.isEmpty()) {
            final JMenu addRequestToTabMenu = new JMenu("Add request to");
            addToTabMenuItems.forEach(addRequestToTabMenu::add);
            menuItems.add(addRequestToTabMenu);
        }

        return menuItems;
    }

    private JMenuItem createIntruderTemplateMenuItem(GeneralSettings generalSettings, URL targetUrl, String request, Range selectionRange) {
        final JMenuItem generateIntruderTemplateMenuItem;
        final int startSelectionIndex = selectionRange.startIndexInclusive();
        final int endSelectionIndex = selectionRange.endIndexExclusive();
        if (endSelectionIndex - startSelectionIndex > 0) {
            generateIntruderTemplateMenuItem = createContextMenuItem(() -> {
                final StringBuilder requestModifier = new StringBuilder(request);
                requestModifier.insert(startSelectionIndex, TemplateUtils.INTRUDER_PAYLOAD_MARKER);
                requestModifier.insert(endSelectionIndex + 1, TemplateUtils.INTRUDER_PAYLOAD_MARKER);

                generateIntruderTemplate(generalSettings, targetUrl, requestModifier.toString(), Requests.AttackType.batteringram);
            }, "Generate Intruder Template");
        } else {
            generateIntruderTemplateMenuItem = null;
        }
        return generateIntruderTemplateMenuItem;
    }

    private static TemplateGeneratorTabContainer getTemplateGeneratorContainerInstance(GeneralSettings generalSettings) {
        return generalSettings.isDetachedGeneratorWindow() ? TemplateGeneratorWindow.getInstance(generalSettings) : TemplateGeneratorEmbeddedContainer.getInstance(generalSettings);
    }

    private static Set<JMenuItem> createAddRequestToTabContextMenuItems(GeneralSettings generalSettings, String[] requests) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final Consumer<Requests> firstRequestConsumer = firstRequest -> firstRequest.addRaw(requests);
            createContextMenuActionHandlingMultiRequests(template, requests, firstRequestConsumer, "request");
        });
    }

    private static Optional<Map.Entry<String, Component>> getTabComponentByName(JTabbedPane tabbedPane, String generatorTabName) {
        return IntStream.range(0, tabbedPane.getTabCount())
                        .mapToObj(i -> Map.entry(tabbedPane.getTitleAt(i), tabbedPane.getComponentAt(i)))
                        .filter(entry -> entry.getKey().equals(generatorTabName))
                        .findFirst();
    }

    private JMenuItem createTemplateWithHttpRequestContextMenuItem(GeneralSettings generalSettings, byte[] requestBytes, URL targetUrl) {
        final Requests requests = new Requests();
        requests.setRaw(requestBytes);
        return createContextMenuItem(() -> generateTemplate(generalSettings, targetUrl, requests), GENERATE_CONTEXT_MENU_TEXT);
    }

    private List<JMenuItem> createMenuItemsFromHttpResponse(GeneralSettings generalSettings, URL targetUrl, HttpRequestResponse httpRequestResponse, Range selectionRange, ByteUtils byteUtils) {
        final HttpResponse httpResponse = httpRequestResponse.response();
        final byte[] responseBytes = httpResponse.toByteArray().getBytes();
        final TemplateMatcher contentMatcher = TemplateUtils.createContentMatcher(responseBytes, httpResponse.bodyOffset(), new int[]{selectionRange.startIndexInclusive(), selectionRange.endIndexExclusive()}, byteUtils::convertToString);

        final JMenuItem generateTemplateContextMenuItem = createContextMenuItem(() -> generateTemplate(generalSettings, contentMatcher, targetUrl, httpRequestResponse), GENERATE_CONTEXT_MENU_TEXT);

        final List<JMenuItem> menuItems;
        final String[] request = {byteUtils.convertToString(httpRequestResponse.request().toByteArray().getBytes())};
        final Set<JMenuItem> addToTabMenuItems = createAddMatcherToTabContextMenuItems(generalSettings, contentMatcher, request);
        if (addToTabMenuItems.isEmpty()) {
            menuItems = List.of(generateTemplateContextMenuItem);
        } else {
            final JMenu addMatcherToTabMenu = new JMenu("Add matcher to");
            addToTabMenuItems.forEach(addMatcherToTabMenu::add);
            menuItems = Arrays.asList(generateTemplateContextMenuItem, addMatcherToTabMenu);
        }

        return menuItems;
    }

    private static Set<JMenuItem> createAddMatcherToTabContextMenuItems(GeneralSettings generalSettings, TemplateMatcher contentMatcher, String[] httpRequest) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final Consumer<Requests> firstRequestConsumer = firstRequest -> {
                final List<TemplateMatcher> matchers = firstRequest.getMatchers();
                firstRequest.setMatchers(Utils.createNewList(matchers, contentMatcher));
            };
            createContextMenuActionHandlingMultiRequests(template, httpRequest, firstRequestConsumer, "matcher");
        });
    }

    private static void createContextMenuActionHandlingMultiRequests(Template template, String[] httpRequests, Consumer<Requests> firstTemplateRequestConsumer, String errorMessageContext) {
        final List<Requests> requests = template.getRequests();

        final int requestSize = requests.size();
        if (requestSize == 0) {
            final Requests newRequest = new Requests();
            newRequest.setRaw(httpRequests);
            template.setRequests(List.of(newRequest));
        } else {
            if (requestSize > 1) {
                JOptionPane.showMessageDialog(null, String.format("The %s will be added to the first request!", errorMessageContext), "Multiple requests present", JOptionPane.WARNING_MESSAGE);
            }
            firstTemplateRequestConsumer.accept(requests.iterator().next());
        }
    }

    private static Set<JMenuItem> createAddToTabContextMenuItems(GeneralSettings generalSettings, Consumer<Template> templateConsumer) {
        final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);

        return templateGeneratorTabContainer.getTabs().stream().map(tab -> {
            final String tabName = tab.getName();
            // TODO add scrollable menu?
            final Runnable action = () -> templateGeneratorTabContainer.getTab(tabName)
                                                                       .ifPresent(templateGeneratorTab -> templateGeneratorTab.getTemplate().ifPresent(template -> {
                                                                           templateConsumer.accept(template);
                                                                           templateGeneratorTab.setTemplate(template);
                                                                       }));
            return createContextMenuItem(action, tabName);
        }).collect(Collectors.toSet());
    }

    private List<JMenuItem> generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request) {
        final List<JMenuItem> menuItems;
        if (request.chars().filter(c -> c == TemplateUtils.INTRUDER_PAYLOAD_MARKER).count() <= 2) {
            menuItems = List.of(createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, Requests.AttackType.batteringram), GENERATE_CONTEXT_MENU_TEXT));
        } else {
            menuItems = Arrays.stream(Requests.AttackType.values())
                              .map(attackType -> createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, attackType), GENERATE_CONTEXT_MENU_TEXT + " - " + attackType))
                              .collect(Collectors.toList());
        }
        return menuItems;
    }

    private static JMenuItem createContextMenuItem(Runnable runnable, String menuItemText) {
        final JMenuItem menuItem = new JMenuItem(menuItemText);
        menuItem.addActionListener((ActionEvent e) -> runnable.run());
        return menuItem;
    }

    private void generateTemplate(GeneralSettings generalSettings, TemplateMatcher contentMatcher, URL targetUrl, HttpRequestResponse requestResponse) {
        final int statusCode = requestResponse.response().statusCode();

        final Requests requests = new Requests();
        requests.setRaw(requestResponse.request().toByteArray().getBytes());
        requests.setMatchers(contentMatcher, new Status(statusCode));

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request, Requests.AttackType attackType) {
        final Requests requests = new Requests();
        final TransformedRequest intruderRequest = TemplateUtils.transformRequestWithPayloads(attackType, request);
        requests.setTransformedRequest(intruderRequest);

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateTemplate(GeneralSettings generalSettings, URL targetUrl, Requests requests) {
        final String author = generalSettings.getAuthor();
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Template template = new Template("template-id", info, requests);
        final String normalizedTemplate = TemplateUtils.normalizeTemplate(YamlUtil.dump(template));

        final NucleiGeneratorSettings nucleiGeneratorSettings = new NucleiGeneratorSettings.Builder(generalSettings, targetUrl, normalizedTemplate)
                .withYamlFieldDescriptionMap(this.yamlFieldDescriptionMap)
                .build();

        SwingUtilities.invokeLater(() -> {
            try {
                final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);
                templateGeneratorTabContainer.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));

                if (!generalSettings.isDetachedGeneratorWindow()) {
                    configureEmbeddedGeneratorTab(generalSettings, templateGeneratorTabContainer);
                }
            } catch (Throwable e) {
                JOptionPane.showMessageDialog(null, "There was an error while trying to complete the requested action. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
                generalSettings.logError("Error while trying to generate/show the generated template", e);
            }
        });
    }

    private void configureEmbeddedGeneratorTab(GeneralSettings generalSettings, TemplateGeneratorTabContainer templateGeneratorTabContainer) {
        if (getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).isEmpty()) {
            this.nucleiTabbedPane.addTab(GENERATOR_TAB_NAME, templateGeneratorTabContainer.getComponent());

            final TemplateGeneratorTabbedPane tabbedPane = templateGeneratorTabContainer.getTabbedPane();
            tabbedPane.addChangeListener(e -> {
                if (((JTabbedPane) e.getSource()).getTabCount() == 0) {
                    getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).map(Map.Entry::getValue)
                                                                                    .ifPresentOrElse(generatorTab -> this.nucleiTabbedPane.remove(generatorTab),
                                                                                                     () -> generalSettings.logError("Nuclei Generator tab was not present to remove."));
                    Arrays.stream(tabbedPane.getChangeListeners())
                          .forEach(tabbedPane::removeChangeListener);
                }
            });
        }
    }

    private static class EmptyRange implements Range {
        @Override
        public int startIndexInclusive() {
            return 0;
        }

        @Override
        public int endIndexExclusive() {
            return 0;
        }
    }
}
